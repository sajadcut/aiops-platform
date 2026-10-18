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
from domain.contracts.context import set_trace_id
from vmmcpagent.audit import audit_frame
from vmmcpagent.connector import LocalVMConnector as _SessionCredentials

_MAX_FRAME = 1024 * 1024
_MAX_REPLAY_ENTRIES = 4096
_MAX_LEASE_SECONDS = 190

def _monotonic_time() -> float:
    """Host-local elapsed-time clock; never compare wall clocks across VMs."""
    return time.monotonic()

_TARGET = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,253}\Z")


def broker_url() -> str:
    base = str(settings.VM_AGENT_CONTROL_PLANE_WS_URL or "").strip()
    parsed = urlsplit(base)
    lab_plain_ws = (
        parsed.scheme == "ws" and settings.VM_AGENT_WS_TEST_MODE
        and settings.APP_ENV == "test"
    )
    if (not (parsed.scheme == "wss" or lab_plain_ws)
            or not parsed.hostname or parsed.username
            or parsed.password or parsed.query or parsed.fragment
            or parsed.path.rstrip("/") != "/api/v1/vm-agents/connect"):
        raise RuntimeError("vm_agent_control_plane_wss_url_invalid")
    target = settings.VM_AGENT_TARGET
    if not target or not _TARGET.fullmatch(target):
        raise RuntimeError("vm_agent_target_invalid")
    return base.rstrip("/") + "/" + quote(target, safe="")


_WRITE_TOOLS = frozenset({"start_service", "restart_service", "reload_service", "config_change_apply"})

def outbound_tls_context() -> ssl.SSLContext:
    """Explicitly configurable peer validation; never downgrade WSS to ws://."""
    if settings.VM_AGENT_TLS_VERIFY:
        return ssl.create_default_context(cafile=settings.VM_AGENT_CA_BUNDLE_PATH or None)
    # The connection remains encrypted but is UNAUTHENTICATED and therefore
    # vulnerable to active MITM and theft of the sudo credential exchanged
    # on first connection. Require an explicit, opt-in on each destination.
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    logger.warning("vm_agent_tls_peer_verification_disabled",
                   target=settings.VM_AGENT_TARGET,
                   risk="UNAUTHENTICATED_WSS_MITM_CAN_STEAL_SUDO_PASSWORD")
    return context



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
    lab_plain_ws = url.startswith("ws://")
    if lab_plain_ws:
        from integrations.vm.agent_ws_test_cipher import _key
        _key(settings.VM_AGENT_WS_TEST_KEY)  # fail closed before any connection
        logger.warning("vm_agent_lab_ws80_no_tls",
                       target=settings.VM_AGENT_TARGET,
                       protection="mutual_psk_aes256gcm",
                       risk="HTTP_UPGRADE_AND_BEARER_HEADERS_VISIBLE")
    context = None if lab_plain_ws else outbound_tls_context()
    delay = 1
    logger.info("vm_agent_connection_configured", target=settings.VM_AGENT_TARGET,
                tls_verify=settings.VM_AGENT_TLS_VERIFY and not lab_plain_ws,
                transport="ws+psk_aead_test_only" if lab_plain_ws else "wss")
    # Retain all unexpired IDs. Never silently evict a still-valid command:
    # doing so would permit replay of a completed write within its TTL.
    completed: deque[tuple[str, float]] = deque()
    known: set[str] = set()
    while True:
        try:
            async with connect(
                url, ssl=context,
                additional_headers={"Authorization": "Bearer " + secret},
                open_timeout=10, ping_interval=20, ping_timeout=20,
                max_size=_MAX_FRAME, max_queue=8, close_timeout=5,
            ) as raw_socket:
                socket = raw_socket
                if lab_plain_ws:
                    from integrations.vm.agent_ws_test_cipher import secure_agent
                    socket = await secure_agent(raw_socket, settings.VM_AGENT_TARGET,
                                                settings.VM_AGENT_WS_TEST_KEY)
                delay = 1
                _SessionCredentials.clear_session_credentials()
                channel_provisioned = False
                prepared: dict[str, tuple[str, dict, float]] = {}
                logger.info("vm_agent_outbound_channel_connected", target=settings.VM_AGENT_TARGET,
                            tls_verify=settings.VM_AGENT_TLS_VERIFY)
                audit_frame("vm_agent_ws_connection_established",
                            {"type": "channel_connected", "target": settings.VM_AGENT_TARGET})

                async def execute_tool(tool: str, args: dict) -> dict:
                    try:
                        return await _call("vm_agent", tool, args)
                    except Exception as exc:
                        # Never log secret-bearing commands or exception bodies.
                        logger.warning("vm_agent_outbound_operation_failed",
                                       target=settings.VM_AGENT_TARGET,
                                       tool=tool, error_type=type(exc).__name__)
                        return _execution_failure(tool, "agent_execution_failed",
                                                  sent_to_executor=True)

                async def send_result(tool: str, ident: str, result: dict,
                                      received_at: float, *, executed: bool) -> None:
                    payload = json.dumps({"type": "result", "id": ident, "result": result},
                                         separators=(",", ":"), default=str)
                    if len(payload.encode("utf-8")) > _MAX_FRAME:
                        payload = json.dumps({
                            "type": "result", "id": ident,
                            "result": _execution_failure(
                                tool, "agent_result_too_large",
                                sent_to_executor=executed),
                        })
                    await socket.send(payload)
                    audit_frame("vm_agent_ws_response_sent",
                                {"type": "result", "id": ident,
                                 "result": json.loads(payload).get("result")},
                                trace_id=ident,
                                duration_ms=(time.perf_counter() - received_at) * 1000,
                                byte_count=len(payload.encode("utf-8")))

                async for raw in socket:
                    received_at = time.perf_counter()
                    if not isinstance(raw, str) or len(raw.encode("utf-8")) > _MAX_FRAME:
                        audit_frame("vm_agent_ws_request_rejected",
                                    {"type": "oversize_or_binary"}, error_type="frame_limit",
                                    byte_count=len(raw) if isinstance(raw, (str, bytes)) else None)
                        await socket.close(code=1009)
                        break
                    try:
                        request = json.loads(raw)
                    except (ValueError, TypeError):
                        audit_frame("vm_agent_ws_request_rejected",
                                    {"type": "malformed_json"}, byte_count=len(raw.encode("utf-8")),
                                    error_type="json_decode_error")
                        await socket.close(code=1003)
                        break
                    trace = (request.get("id") if isinstance(request, dict)
                             and isinstance(request.get("id"), str)
                             and re.fullmatch(r"[0-9a-f-]{36}", request["id"])
                             else None)
                    set_trace_id(trace or "")
                    audit_frame("vm_agent_ws_request_received", request, trace_id=trace,
                                byte_count=len(raw.encode("utf-8")))
                    if isinstance(request, dict) and request.get("type") == "credentials":
                        if (channel_provisioned or request.get("version") != 1
                                or request.get("target") != settings.VM_AGENT_TARGET):
                            audit_frame("vm_agent_ws_request_rejected", request,
                                        trace_id=trace, error_type="policy_rejected")
                            await socket.close(code=1008)
                            break
                        try:
                            _SessionCredentials.set_session_credentials(
                                request.get("username"), request.get("password"))
                        except (PermissionError, TypeError, ValueError):
                            audit_frame("vm_agent_ws_request_rejected", request,
                                        trace_id=trace, error_type="policy_rejected")
                            await socket.close(code=1008)
                            break
                        channel_provisioned = True
                        acknowledgment = {
                            "type": "credentials_ack", "ok": True,
                            "target": settings.VM_AGENT_TARGET,
                            "username": settings.VM_AGENT_EXEC_USERNAME,
                            "lease_protocol": "relative_monotonic_v2",
                        }
                        wire_ack = json.dumps(acknowledgment, separators=(",", ":"))
                        await socket.send(wire_ack)
                        audit_frame("vm_agent_ws_response_sent", acknowledgment,
                                    duration_ms=(time.perf_counter() - received_at) * 1000,
                                    byte_count=len(wire_ack.encode("utf-8")))
                        # Never include the password in command/result frames.
                        continue
                    if settings.APP_ENV == "production" and not channel_provisioned:
                        audit_frame("vm_agent_ws_request_rejected", request,
                                    trace_id=trace, error_type="policy_rejected")
                        await socket.close(code=1008)
                        break
                    if isinstance(request, dict) and request.get("type") == "execute_commit":
                        ident = request.get("id")
                        if (not isinstance(ident, str) or ident not in prepared):
                            audit_frame("vm_agent_ws_request_rejected", request,
                                        trace_id=trace, error_type="policy_rejected")
                            await socket.close(code=1008)
                            break
                        tool, args, deadline = prepared.pop(ident)
                        executed = _monotonic_time() <= deadline
                        result = (await execute_tool(tool, args) if executed else
                                  _execution_failure(tool, "request_expired",
                                                     sent_to_executor=False))
                        await send_result(tool, ident, result, received_at, executed=executed)
                        set_trace_id("")
                        continue
                    if not isinstance(request, dict) or request.get("type") != "execute":
                        audit_frame("vm_agent_ws_request_rejected", request,
                                    trace_id=trace, error_type="policy_rejected")
                        await socket.close(code=1008)
                        break
                    ident = request.get("id")
                    tool = request.get("tool")
                    args = request.get("arguments")
                    expires = request.get("expires_at")
                    ttl = request.get("ttl_seconds")
                    relative = type(ttl) is int and expires is None
                    legacy = type(expires) is int and ttl is None
                    if (not isinstance(ident, str)
                            or not re.fullmatch(r"[0-9a-f-]{36}", ident)
                            or not isinstance(tool, str)
                            or tool not in _TOOL_SCHEMAS["vm_agent"]
                            or not isinstance(args, dict)
                            or args.get("target") != settings.VM_AGENT_TARGET
                            or not (relative or legacy)
                            or (relative and not 1 <= ttl <= _MAX_LEASE_SECONDS)):
                        audit_frame("vm_agent_ws_request_rejected", request,
                                    trace_id=trace, error_type="policy_rejected")
                        await socket.close(code=1008)
                        break
                    # Relative leases use *only* this VM's monotonic clock.
                    # Legacy frames remain supported for rolling upgrades.
                    now = _monotonic_time()
                    wall_now = int(time.time()) if legacy else None
                    deadline = (now + ttl if relative
                                else now + max(0, expires - wall_now))
                    while completed and completed[0][1] < now:
                        known.discard(completed.popleft()[0])
                    executed = False
                    if ident in known:
                        result = _execution_failure(tool, "duplicate_request_refused",
                                                    sent_to_executor=True)
                    elif legacy and (expires < wall_now or expires > wall_now + 191):
                        result = _execution_failure(tool, "request_expired",
                                                    sent_to_executor=False)
                    elif len(completed) >= _MAX_REPLAY_ENTRIES:
                        result = _execution_failure(tool, "request_replay_guard_full",
                                                    sent_to_executor=False)
                    else:
                        known.add(ident)
                        completed.append((ident, deadline + 2))
                        if relative and tool in _WRITE_TOOLS:
                            # Two-phase commit: the API must re-check its own
                            # monotonic deadline *after* the VM receives the
                            # command. Without execute_commit, no write starts.
                            prepared[ident] = (tool, args, deadline)
                            response = json.dumps({"type": "execute_ready", "id": ident},
                                                  separators=(",", ":"))
                            await socket.send(response)
                            audit_frame("vm_agent_ws_response_sent",
                                        {"type": "execute_ready", "id": ident},
                                        trace_id=ident,
                                        duration_ms=(time.perf_counter() - received_at) * 1000,
                                        byte_count=len(response.encode("utf-8")))
                            set_trace_id("")
                            continue
                        executed = True
                        result = await execute_tool(tool, args)
                    await send_result(tool, ident, result, received_at, executed=executed)
                    set_trace_id("")
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            logger.warning("vm_agent_outbound_disconnected",
                           target=settings.VM_AGENT_TARGET,
                           error_type=type(exc).__name__)
            audit_frame("vm_agent_ws_channel_error",
                        {"type": "channel_error", "target": settings.VM_AGENT_TARGET},
                        error_type=type(exc).__name__)
        finally:
            audit_frame("vm_agent_ws_channel_closed",
                        {"type": "channel_closed", "target": settings.VM_AGENT_TARGET})
            set_trace_id("")
            _SessionCredentials.clear_session_credentials()
        # Reconnect is for a fresh channel only. Never retransmit a write.
        await asyncio.sleep(delay)
        delay = min(delay * 2, 30)
