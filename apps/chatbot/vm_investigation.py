"""Bounded adaptive read-only VM investigation through the existing governed MCP.

No commands, approval bypass or LLM-controlled arbitrary tool access. Every
selected check is an explicit, pre-registered VM telemetry action.
"""
from __future__ import annotations

import asyncio
import time
from datetime import datetime, timezone
from typing import Any, Awaitable, Callable

from apps.execution_service import ExecutionRequest, ExecutionResult, ExecutionService
from integrations.vm.mcp_client import VMEdgeMCPClient

_MAX_STEPS = 7
_DEADLINE_SECONDS = 100.0
_PER_STEP_SECONDS = 24.0
_SCOPES = frozenset({"host_performance", "service_start_failure"})


async def run_vm_investigation(
    *, target: str, scope: str, service: str | None = None,
    execute: Callable[[ExecutionRequest], Awaitable[ExecutionResult]] | None = None,
) -> dict[str, Any]:
    """Collect a bounded diagnostic chain, preserving failures and provenance."""
    if scope not in _SCOPES:
        raise ValueError("invalid_vm_investigation_scope")
    if scope == "service_start_failure" and not service:
        raise ValueError("vm_investigation_service_required")
    executor = execute or ExecutionService.execute
    start = time.monotonic()
    observations: list[dict[str, Any]] = []
    checked: set[str] = set()
    deadline_exceeded = False

    async def check(action: str, why: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        nonlocal deadline_exceeded
        if action not in VMEdgeMCPClient.READ_TOOLS or action in checked or len(checked) >= _MAX_STEPS:
            raise RuntimeError("unregistered_or_repeated_investigation_action")
        checked.add(action)
        remaining = _DEADLINE_SECONDS - (time.monotonic() - start)
        if remaining <= 0:
            deadline_exceeded = True
            entry = {"tool": action, "why": why, "status": "not_executed", "error": "investigation_deadline_exceeded"}
            observations.append(entry)
            return entry
        entry: dict[str, Any] = {"tool": action, "why": why, "status": "unavailable"}
        try:
            request = ExecutionRequest(
                tool_name="vm_telemetry", action=action, target=target,
                parameters=params or {}, timeout=min(30, max(1, int(remaining))),
                agent_name="chatbot-investigation",
            )
            result = await asyncio.wait_for(executor(request), timeout=min(_PER_STEP_SECONDS, remaining))
            data = result.result if isinstance(result.result, dict) else {}
            entry["observed_at"] = result.execution_completed_at.isoformat()
            entry["source"] = "vm_mcp"
            if result.success and data.get("success") is True:
                entry["status"] = "observed"
                entry["data"] = data
            else:
                entry["status"] = "blocked" if result.execution_blocked else "unavailable"
                entry["error"] = str(result.reason or result.error or data.get("error") or "tool_failed")[:100]
        except asyncio.TimeoutError:
            entry["error"] = "diagnostic_timeout"
        except PermissionError:
            entry["status"] = "blocked"
            entry["error"] = "policy_denied"
        except Exception:
            # Avoid surfacing host commands, credentials, or remote exception text.
            entry["error"] = "tool_execution_failed"
        observations.append(entry)
        return entry

    if scope == "host_performance":
        await check("collect_vm_metrics", "CPU, memory, swap, load and I/O wait")
        await check("memory_diagnostics", "RAM/swap pressure and process memory usage")
        await check("disk_status", "Filesystem capacity and inode saturation")
        await check("process_snapshot", "Current top processes")
        await check("network_status", "Interface and route state")
    else:
        assert service is not None
        status = await check("service_status", "Current systemd state", {"service": service})
        # Even if systemd is active, application-level health remains unknown.
        await check("service_logs", "Recent application/systemd failures", {"service": service, "limit": 40})
        await check("service_runtime_discovery", "Runtime and systemd unit evidence", {"service": service})
        await check("process_status", "Application process evidence", {"process": service})
        await check("collect_vm_metrics", "CPU, memory and swap pressure")
        await check("disk_status", "Filesystem capacity and inode pressure")
        logs = next((x.get("data") for x in observations if x["tool"] == "service_logs" and x["status"] == "observed"), None)
        lines = logs.get("logs") if isinstance(logs, dict) else None
        text = "\n".join(str(x) for x in lines[-40:])[:8000].lower() if isinstance(lines, list) else ""
        if any(token in text for token in ("syntax error", "invalid directive", "parse error", "configuration error")):
            await check("config_validate", "Config-related log errors require independent syntax validation", {"service": service})

    succeeded = sum(item["status"] == "observed" for item in observations)
    return {
        "success": succeeded > 0,  # At least one successful observation, NOT recovered/healthy.
        "target": target, "scope": scope, "service": service,
        "source": "governed_vm_mcp", "observed_at": datetime.now(timezone.utc).isoformat(),
        "observations": observations, "steps_executed": len(checked),
        "max_steps": _MAX_STEPS, "partial": succeeded != len(observations) or deadline_exceeded,
        "application_health_verified": False, "root_cause_confirmed": False,
        "read_only": True, "elapsed_seconds": round(time.monotonic() - start, 3),
    }
