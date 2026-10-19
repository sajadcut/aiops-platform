"""Execute only model-selected, read-only VM diagnostics with live identity proof.

The LLM supplies an enum tool name, never target, unit, URL, endpoint or path.
Source metadata is untrusted; a matching independently verified VM MCP
service_status is required for every step.
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from typing import Any

from domain.contracts.config import settings

ALLOWED_FOLLOWUPS = frozenset({
    "service_logs", "service_status", "service_runtime_discovery",
    "service_config_discovery", "dependency_investigation", "network_status",
})


async def run_verified_dependency_followup(
    client: Any, state: dict, proposed: list[str],
) -> list[dict]:
    if client is None or not isinstance(proposed, list):
        return []
    context = state.get("context") or {}
    discovery = context.get("host_discovery") or {}
    target = str(discovery.get("verified_target") or "")
    service = str(discovery.get("verified_runtime_service") or "")
    named = str(state.get("service_name") or "")
    if (
        discovery.get("status") != "verified_by_vm_mcp"
        or not target or not service or not named
        or service.casefold().removesuffix(".service")
            != named.casefold().removesuffix(".service")
    ):
        return []
    proof = any(
        isinstance(row, dict) and row.get("source") == "vm_mcp"
        and isinstance(row.get("raw_data"), dict)
        and row["raw_data"].get("diagnostic") == "service_status"
        and row["raw_data"].get("success") is True
        and row["raw_data"].get("load_state") == "loaded"
        and str(row["raw_data"].get("target") or "").casefold() == target.casefold()
        and str(row["raw_data"].get("service") or "").casefold().removesuffix(".service")
            == service.casefold().removesuffix(".service")
        for row in (context.get("evidence") or [])[:200]
    )
    if not proof:
        return []
    selected = list(dict.fromkeys(
        item for item in proposed[:4]
        if isinstance(item, str) and item in ALLOWED_FOLLOWUPS
    ))[:2]
    evidence: list[dict] = []
    for action in selected:
        tool = getattr(client, action, None)
        if not callable(tool):
            continue
        try:
            timeout = max(3.0, min(15.0, float(settings.MCP_TIMEOUT_SECONDS)))
            result = await asyncio.wait_for(
                tool(target, service) if action != "network_status" else tool(target),
                timeout=timeout,
            )
            if not isinstance(result, dict) or result.get("success") is not True:
                continue
            if str(result.get("target") or "").casefold() != target.casefold():
                continue
            if action != "network_status" and (
                str(result.get("service") or "").casefold().removesuffix(".service")
                != service.casefold().removesuffix(".service")
            ):
                continue
            # Source identity comes from trusted control plane; no LLM fact is
            # emitted as live evidence, and raw config/secret values are never
            # requested by these registered MCP read-only methods.
            evidence.append({
                "type": "telemetry",
                "source": "vm_mcp",
                "reference": (
                    f"verified-followup:{state.get('incident_id')}:{action}"
                )[:240],
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "raw_data": {
                    **result, "diagnostic": action, "target": target,
                    "service": service,
                    "binding": "independent_vm_mcp_service_status",
                    "followup_selected_from": "llm_read_only_enum",
                },
            })
        except Exception:
            # A failed optional read must not block analysis or authorize write.
            continue
    return evidence
