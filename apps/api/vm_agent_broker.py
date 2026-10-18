"""Authenticated, target-bound, outbound-agent WebSocket broker.

The agent initiates the connection. Only the API execution path may dispatch
allowlisted MCP tools; this module exposes no arbitrary command runner.
Connections are deliberately process-local: deploy a SINGLE API worker for
agent_pull until a distributed broker is introduced. Missing sessions fail
closed; no SSH or HTTP-agent fallback is attempted.
"""
from __future__ import annotations

import asyncio
import hmac
import json
import re
import time
from dataclasses import dataclass, field
from typing import Any
from uuid import uuid4

from fastapi import WebSocket
from starlette.websockets import WebSocketDisconnect

from domain.contracts.config import settings
from domain.contracts.logging import logger

MAX_FRAME = 1024 * 1024
# One outstanding RPC per VM: agent executes sequentially. Do not queue an
# approved write behind a slow read that may expire before it even starts.
MAX_PENDING_PER_AGENT = 1
MAX_RESULT_SECONDS = 190
_EXEC_USERNAME = re.compile(r"[a-z_][a-z0-9_-]{0,31}\\Z")
WRITE_TOOLS = frozenset({"start_service", "restart_service", "reload_service", "config_change_apply"})


class AgentDisconnected(RuntimeError):
    pass


@dataclass
class AgentSession:
    target: str
    socket: WebSocket
    connected_at: float = field(default_factory=time.monotonic)
    ready: bool = False
    pending: dict[str, asyncio.Future] = field(default_factory=dict)
    sending: asyncio.Lock = field(default_factory=asyncio.Lock)

    def fail_pending(self) -> None:
        for future in self.pending.values():
            if not future.done():
                future.set_exception(AgentDisconnected("agent_channel_disconnected"))
        self.pending.clear()


class OutboundAgentBroker:
    def __init__(self) -> None:
        self.sessions: dict[str, AgentSession] = {}
        self.lock = asyncio.Lock()

    def is_connected(self, target: str) -> bool:
        session = self.sessions.get(target)
        return session is not None and session.ready

    async def connect(self, socket: WebSocket, target: str) -> None:
        """Authenticate before accepting; reject duplicate host identities."""
        if settings.VM_EXECUTION_BACKEND != "agent_pull":
            await socket.close(code=4403)
            return
        secret = settings.VM_AGENT_TOKENS.get(target)
        auth = socket.headers.get("authorization", "")
        # Never accept a browser cookie, URL token, or an identity not explicitly
        # configured by the operator.
        if (not secret or len(secret.encode("utf-8")) < 32
                or not hmac.compare_digest(auth, "Bearer " + secret)):
            await socket.close(code=4401)
            return
        async with self.lock:
            if target in self.sessions:
                await socket.close(code=4409)
                return
            await socket.accept()
            session = AgentSession(target, socket)
            self.sessions[target] = session
        try:
            # First authenticated WSS message provisions credentials for this
            # exact registered VM. Neither sudo password nor identity is part
            # of an MCP request, audit entry, response or URL.
            credentials = settings.VM_AGENT_EXECUTION_CREDENTIALS.get(target)
            if credentials is None and settings.APP_ENV == "production":
                await socket.close(code=4403)
                return
            if credentials is not None:
                username = credentials.get("username")
                password = credentials.get("password")
                if (not isinstance(username, str) or not _EXEC_USERNAME.fullmatch(username)
                        or username == "root" or not isinstance(password, str)
                        or not password or any(ch in password for ch in ("\\n", "\\r", "\\x00"))):
                    await socket.close(code=4403)
                    return
                await socket.send_text(json.dumps({
                    "type": "credentials", "version": 1, "target": target,
                    "username": username, "password": password,
                }, separators=(",", ":")))
                try:
                    reply = await asyncio.wait_for(socket.receive_text(), timeout=10)
                    acknowledgment = json.loads(reply)
                except (asyncio.TimeoutError, ValueError, TypeError, WebSocketDisconnect):
                    await socket.close(code=4408)
                    return
                if (not isinstance(acknowledgment, dict)
                        or acknowledgment.get("type") != "credentials_ack"
                        or acknowledgment.get("target") != target
                        or acknowledgment.get("username") != username
                        or acknowledgment.get("ok") is not True):
                    await socket.close(code=4403)
                    return
            session.ready = True
            logger.info("vm_outbound_agent_connected", target=target)
            while True:
                data = await socket.receive_text()
                if len(data.encode("utf-8")) > MAX_FRAME:
                    await socket.close(code=1009)
                    break
                try:
                    payload = json.loads(data)
                except (ValueError, TypeError):
                    await socket.close(code=1003)
                    break
                if not isinstance(payload, dict) or payload.get("type") != "result":
                    await socket.close(code=1008)
                    break
                ident = payload.get("id")
                # A request ID belongs solely to its own authenticated
                # session. Unknown/late result IDs are never applied.
                if not isinstance(ident, str) or ident not in session.pending:
                    continue
                result = payload.get("result")
                if not isinstance(result, dict):
                    await socket.close(code=1008)
                    break
                future = session.pending.pop(ident)
                if not future.done():
                    future.set_result(result)
        except (WebSocketDisconnect, RuntimeError):
            pass
        finally:
            async with self.lock:
                if self.sessions.get(target) is session:
                    self.sessions.pop(target, None)
            session.fail_pending()
            logger.info("vm_outbound_agent_disconnected", target=target)

    async def dispatch(self, target: str, tool: str, args: dict[str, Any],
                       *, timeout: float = 30) -> dict[str, Any]:
        """Never retry an ambiguous write; surface UNKNOWN for reconciliation."""
        from integrations.vm.mcp_client import VMEdgeMCPClient

        if settings.VM_EXECUTION_BACKEND != "agent_pull":
            raise PermissionError("vm_agent_pull_not_enabled")
        if target not in settings.VM_AGENT_TOKENS:
            raise PermissionError("vm_target_not_allowed")
        if tool not in VMEdgeMCPClient.READ_TOOLS | VMEdgeMCPClient.WRITE_TOOLS:
            raise PermissionError("vm_agent_tool_not_allowed")
        if args.get("target") != target:
            raise PermissionError("vm_agent_target_binding_invalid")
        if tool in {"start_service", "restart_service", "reload_service"}:
            if not (str(args.get("approval_id") or "").strip()
                    and str(args.get("incident_id") or "").strip()
                    and str(args.get("service") or "").strip()):
                raise PermissionError("vm_agent_write_approval_context_required")
        if tool == "config_change_apply":
            from apps.config_change_authorization import verify_claim
            verify_claim(args.get("claims"), args.get("signature"),
                         target=target, service=str(args.get("service") or ""))
        session = self.sessions.get(target)
        # No command has been sent if the agent was disconnected or busy.
        if session is None or not session.ready:
            return self._not_dispatched(tool, "agent_not_connected")
        if len(session.pending) >= MAX_PENDING_PER_AGENT:
            return self._not_dispatched(tool, "agent_queue_full")
        deadline_seconds = min(max(float(timeout), 1), MAX_RESULT_SECONDS)
        request_id = str(uuid4())
        future = asyncio.get_running_loop().create_future()
        session.pending[request_id] = future
        message = {
            "type": "execute", "id": request_id, "target": target,
            "tool": tool, "arguments": args,
            "expires_at": int(time.time() + deadline_seconds),
        }
        logger.info("vm_outbound_dispatch_started", target=target, tool=tool,
                    request_id=request_id)
        try:
            async with session.sending:
                if self.sessions.get(target) is not session:
                    raise AgentDisconnected("agent_session_replaced")
                await session.socket.send_text(json.dumps(message, separators=(",", ":")))
            result = await asyncio.wait_for(future, timeout=deadline_seconds)
            logger.info("vm_outbound_dispatch_completed", target=target,
                        tool=tool, request_id=request_id,
                        success=result.get("success") is True)
            return result
        except asyncio.CancelledError:
            # Client/API task cancellation does not cancel an already sent
            # operation on the host. Audit its possibly committed outcome.
            logger.warning("vm_outbound_dispatch_cancelled_unknown",
                           target=target, tool=tool, request_id=request_id,
                           requires_reconciliation=tool in WRITE_TOOLS)
            raise
        except (asyncio.TimeoutError, RuntimeError, OSError, WebSocketDisconnect):
            logger.warning("vm_outbound_dispatch_unconfirmed", target=target,
                           tool=tool, request_id=request_id)
            return self._unavailable(tool, "agent_result_unconfirmed")
        finally:
            session.pending.pop(request_id, None)
            # Consume possible disconnect exception if the result was abandoned.
            if future.done() and not future.cancelled():
                try:
                    future.exception()
                except (AgentDisconnected, asyncio.CancelledError):
                    pass
            elif not future.done():
                future.cancel()

    @staticmethod
    def _not_dispatched(tool: str, cause: str) -> dict[str, Any]:
        if tool in WRITE_TOOLS:
            return {
                "success": False, "status": cause,
                "execution_outcome": "NOT_STARTED",
                "reason": cause, "production_write_performed": False,
            }
        raise AgentDisconnected(cause)

    async def shutdown(self) -> None:
        async with self.lock:
            sessions = list(self.sessions.values())
            self.sessions.clear()
        for session in sessions:
            session.fail_pending()
            try:
                await session.socket.close(code=1001)
            except (OSError, RuntimeError, WebSocketDisconnect):
                pass

    @staticmethod
    def _unavailable(tool: str, cause: str) -> dict[str, Any]:
        if tool in WRITE_TOOLS:
            return {
                "success": False, "status": "execution_outcome_unknown",
                "execution_outcome": "UNKNOWN",
                "reason": cause, "requires_independent_reconciliation": True,
                "production_write_performed": None,
            }
        raise AgentDisconnected(cause)


broker = OutboundAgentBroker()
