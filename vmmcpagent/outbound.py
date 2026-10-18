"""Puppet-style, agent-initiated outbound WebSocket execution transport.

No listening socket and no incoming SSH/HTTP ports are required on this VM.
TLS, exact target binding, signed configuration approvals and the original
allowlisted MCP dispatch remain mandatory. Never replay write requests.
"""
from __future__ import annotations

import asyncio
import json
import re
import ssl
import time
from collections import deque
from urllib.parse import quote, urlsplit

from domain.contracts.config import settings
from domain.contracts.logging import logger
from vmmcpagent.connector import LocalVMConnector as _SessionCredentials

_MAX_FRAME = 1024 * 1024
_MAX_REPLAY_ENTRIES = 4096
_TARGET = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,253}\Z")


def broker_url() -> str:
    base = str(settings.VM_AGENT_CONTROL_PLANE_WS_URL or "").strip()
    parsed = urlsplit(base)
    if (parsed.scheme != "wss" or not parsed.hostname or parsed.username
            or parsed.password or parsed.query or parsed.fragment
            or parsed.path.rstrip("/") != "/api/v1/vm-agents/connect"):
        raise RuntimeError("vm_agent_control_plane_wss_url_invalid")
    target = settings.VM_AGENT_TARGET
    if not target or not _TARGET.fullmatch(target):
        raise RuntimeError("vm_agent_target_invalid")
    return base.rstrip("/") + "/" + quote(target, safe="")


_WRITE_TOOLS = frozenset({"start_service", "restart_service", "reload_service", "config_change_apply"})


def _execution_failure(tool: str, reason: str, *, sent_to_executor: bool) -> dict:
    """A write may already have completed even if its response cannot be sent."""
    if tool in _WRITE_TOOLS:
        if sent_to_executor:
            return {"success": False, "status": "execution_outcome_unknown",
                    "execution_outcome": "UNKNOWN",
                    "reason": reason, "requires_independent_reconciliation": True,
                    "production_write_performed": None}
        return {"success": False, "status": reason,
                "execution_outcome": "NOT_STARTED", "production_write_performed": False}
    return {"success": False, "status": reason}


async def run_outbound_forever() -> None:
    """Reconnect with bounded backoff, but NEVER resend an interrupted write."""
    # websockets.asyncio is available in websockets >= 14.
    from websockets.asyncio.client import connect

    from apps.mcp_server.main import _TOOL_SCHEMAS, _call
    from vmmcpagent.connector import LocalVMConnector

    LocalVMConnector()  # fail early if root, SSH or per-service controls invalid
    secret = settings.VM_AGENT_BEARER_TOKEN or ""
    if len(secret.encode("utf-8")) < 32 or not settings.MCP_SERVER_REQUIRE_AUTH:
        raise RuntimeError("vm_agent_strong_bearer_and_auth_required")
    if settings.SSH_ENABLED:
        raise RuntimeError("vm_agent_outbound_forbids_ssh")
    url = broker_url()
    context = ssl.create_default_context(cafile=settings.VM_AGENT_CA_BUNDLE_PATH or None)
    delay = 1
    # Retain all unexpired IDs. Never silently evict a still-valid command:
    # doing so would permit replay of a completed write within its TTL.
    completed: deque[tuple[str, int]] = deque()
    known: set[str] = set()
    while True:
        try:
            async with connect(
                url, ssl=context,
                additional_headers={"Authorization": "Bearer " + secret},
                open_timeout=10, ping_interval=20, ping_timeout=20,
                max_size=_MAX_FRAME, max_queue=8, close_timeout=5,
            ) as socket:
                delay = 1
                _SessionCredentials.clear_session_credentials()
                channel_provisioned = False
                logger.info("vm_agent_outbound_channel_connected", target=settings.VM_AGENT_TARGET)
                async for raw in socket:
                    if not isinstance(raw, str) or len(raw.encode("utf-8")) > _MAX_FRAME:
                        await socket.close(code=1009)
                        break
                    try:
                        request = json.loads(raw)
                    except (ValueError, TypeError):
                        await socket.close(code=1003)
                        break
                    if isinstance(request, dict) and request.get("type") == "credentials":
                        if (channel_provisioned or request.get("version") != 1
                                or request.get("target") != settings.VM_AGENT_TARGET):
                            await socket.close(code=1008)
                            break
                        try:
                            _SessionCredentials.set_session_credentials(
                                request.get("username"), request.get("password"))
                        except (PermissionError, TypeError, ValueError):
                            await socket.close(code=1008)
                            break
                        channel_provisioned = True
                        await socket.send(json.dumps({
                            "type": "credentials_ack", "ok": True,
                            "target": settings.VM_AGENT_TARGET,
                            "username": settings.VM_AGENT_EXEC_USERNAME,
                        }, separators=(",", ":")))
                        # Never include the password in command/result frames.
                        continue
                    if settings.APP_ENV == "production" and not channel_provisioned:
                        await socket.close(code=1008)
                        break
                    if not isinstance(request, dict) or request.get("type") != "execute":
                        await socket.close(code=1008)
                        break
                    ident = request.get("id")
                    tool = request.get("tool")
                    args = request.get("arguments")
                    expires = request.get("expires_at")
                    if (not isinstance(ident, str)
                            or not re.fullmatch(r"[0-9a-f-]{36}", ident)
                            or not isinstance(tool, str)
                            or tool not in _TOOL_SCHEMAS["vm_agent"]
                            or not isinstance(args, dict)
                            or args.get("target") != settings.VM_AGENT_TARGET
                            or type(expires) is not int):
                        await socket.close(code=1008)
                        break
                    # Retain every live ID until its execution deadline has
                    # safely passed. On cache saturation reject new commands
                    # rather than evict unexpired IDs (which permits replay).
                    now = int(time.time())
                    while completed and completed[0][1] < now:
                        known.discard(completed.popleft()[0])
                    if ident in known:
                        result = _execution_failure(tool, "duplicate_request_refused", sent_to_executor=True)
                    elif expires < now or expires > now + 191:
                        result = _execution_failure(tool, "request_expired", sent_to_executor=False)
                    elif len(completed) >= _MAX_REPLAY_ENTRIES:
                        result = _execution_failure(tool, "request_replay_guard_full", sent_to_executor=False)
                    else:
                        known.add(ident)
                        completed.append((ident, expires + 2))
                        try:
                            result = await _call("vm_agent", tool, args)
                        except Exception as exc:
                            # No secrets, commands, output or raw exceptions in
                            # control-plane messages/logs.
                            logger.warning("vm_agent_outbound_operation_failed",
                                           target=settings.VM_AGENT_TARGET,
                                           tool=tool, error_type=type(exc).__name__)
                            result = _execution_failure(tool, "agent_execution_failed", sent_to_executor=True)
                    payload = json.dumps({"type": "result", "id": ident, "result": result},
                                         separators=(",", ":"), default=str)
                    if len(payload.encode("utf-8")) > _MAX_FRAME:
                        # The write may be fully committed even though its
                        # response exceeded the transport cap. Never claim no
                        # production change or invite a blind re-execution.
                        payload = json.dumps({
                            "type": "result", "id": ident,
                            "result": _execution_failure(
                                tool, "agent_result_too_large",
                                sent_to_executor=(ident in known)),
                        })
                    await socket.send(payload)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            logger.warning("vm_agent_outbound_disconnected",
                           target=settings.VM_AGENT_TARGET,
                           error_type=type(exc).__name__)
        finally:
            _SessionCredentials.clear_session_credentials()
        # Reconnect is for a fresh channel only. Never retransmit a write.
        await asyncio.sleep(delay)
        delay = min(delay * 2, 30)
