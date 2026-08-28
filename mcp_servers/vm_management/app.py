from __future__ import annotations

import hmac
import json
import logging
import time
import uuid
from typing import Any, Dict

from fastapi import FastAPI, Header, HTTPException, Request, Response
from fastapi.responses import JSONResponse

from mcp_servers.vm_management.config import VMManagementSettings
from mcp_servers.vm_management.inventory import VMInventory
from mcp_servers.vm_management.service import READ_TOOLS, WRITE_TOOLS, VMManagementService
from mcp_servers.vm_management.transports.base import VMTransport
from mcp_servers.vm_management.transports.ssh import OpenSSHTransport

logger = logging.getLogger("vm_management_mcp")


def _rpc_result(rpc_id: Any, result: Dict[str, Any]) -> Dict[str, Any]:
    return {"jsonrpc": "2.0", "id": rpc_id, "result": result}


def _rpc_error(rpc_id: Any, code: int, message: str) -> Dict[str, Any]:
    return {"jsonrpc": "2.0", "id": rpc_id, "error": {"code": code, "message": message}}


def create_app(
    settings: VMManagementSettings | None = None,
    inventory: VMInventory | None = None,
    transport: VMTransport | None = None,
) -> FastAPI:
    settings = settings or VMManagementSettings.from_environment()
    inventory = inventory or VMInventory.load(settings.INVENTORY_PATH)
    transport = transport or OpenSSHTransport(settings)
    service = VMManagementService(settings, inventory, transport)
    sessions: Dict[str, float] = {}

    app = FastAPI(title="VM Management MCP Server", version="1.0.0")
    app.state.vm_settings = settings
    app.state.vm_service = service

    def authorized(authorization: str | None, write: bool = False) -> bool:
        if not settings.REQUIRE_AUTH:
            return True
        if not authorization or not authorization.startswith("Bearer "):
            return False
        supplied = authorization[7:]
        expected = settings.WRITE_TOKEN if write else settings.READ_TOKEN
        if hmac.compare_digest(supplied, expected):
            return True
        return bool(not write and hmac.compare_digest(supplied, settings.WRITE_TOKEN))

    def require_session(session_id: str | None) -> None:
        if not session_id or session_id not in sessions:
            raise HTTPException(status_code=400, detail="mcp_session_required")
        if time.time() - sessions[session_id] > settings.SESSION_TTL_SECONDS:
            sessions.pop(session_id, None)
            raise HTTPException(status_code=400, detail="mcp_session_expired")
        sessions[session_id] = time.time()

    @app.get("/health")
    async def health() -> Dict[str, Any]:
        return {
            "status": "ok",
            "component": "vm-management-mcp",
            "write_enabled": settings.WRITE_ENABLED,
            "inventory_loaded": True,
        }

    @app.post("/mcp")
    async def mcp(
        request: Request,
        authorization: str | None = Header(default=None),
        mcp_session_id: str | None = Header(default=None, alias="Mcp-Session-Id"),
    ) -> Response:
        try:
            payload = await request.json()
        except Exception:
            return JSONResponse(_rpc_error(None, -32700, "parse_error"), status_code=400)
        if not isinstance(payload, dict) or payload.get("jsonrpc") != "2.0" or not isinstance(payload.get("method"), str):
            return JSONResponse(_rpc_error(payload.get("id") if isinstance(payload, dict) else None, -32600, "invalid_request"), status_code=400)

        method = payload["method"]
        rpc_id = payload.get("id")
        params = payload.get("params") or {}

        if method == "initialize":
            if not authorized(authorization):
                raise HTTPException(status_code=401, detail="authentication_required")
            session_id = str(uuid.uuid4())
            sessions[session_id] = time.time()
            body = _rpc_result(rpc_id, {
                "protocolVersion": str(params.get("protocolVersion") or "2025-03-26"),
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": {"name": "vm-management-mcp", "version": "1.0.0"},
            })
            return JSONResponse(body, headers={"Mcp-Session-Id": session_id})

        require_session(mcp_session_id)
        if method == "notifications/initialized":
            if not authorized(authorization):
                raise HTTPException(status_code=401, detail="authentication_required")
            return Response(status_code=202)

        if method == "tools/list":
            if not authorized(authorization):
                raise HTTPException(status_code=401, detail="authentication_required")
            return JSONResponse(_rpc_result(rpc_id, {"tools": service.tools()}))

        if method == "tools/call":
            tool = str(params.get("name", ""))
            arguments = params.get("arguments") or {}
            if tool in WRITE_TOOLS:
                if not authorized(authorization, write=True):
                    raise HTTPException(status_code=403, detail="write_identity_required")
            elif tool in READ_TOOLS:
                if not authorized(authorization):
                    raise HTTPException(status_code=401, detail="authentication_required")
            else:
                return JSONResponse(_rpc_error(rpc_id, -32601, "tool_not_allowed"))
            try:
                result = await service.call(tool, dict(arguments))
            except (PermissionError, ValueError) as exc:
                logger.warning("vm_mcp_blocked tool=%s error=%s", tool, str(exc))
                return JSONResponse(_rpc_error(rpc_id, -32001, str(exc)))
            except Exception as exc:
                logger.exception("vm_mcp_failed tool=%s", tool)
                return JSONResponse(_rpc_error(rpc_id, -32000, "tool_execution_failed"))
            logger.info(
                "vm_mcp_completed tool=%s target=%s mode=%s approval_id=%s duration_ms=%s",
                tool,
                result.get("target"),
                result.get("execution", {}).get("mode"),
                result.get("execution", {}).get("approval_id"),
                result.get("execution", {}).get("duration_ms"),
            )
            content_text = json.dumps(result, separators=(",", ":"), default=str)
            return JSONResponse(_rpc_result(rpc_id, {
                "content": [{"type": "text", "text": content_text}],
                "structuredContent": result,
                "isError": False,
            }))

        return JSONResponse(_rpc_error(rpc_id, -32601, "method_not_found"))

    @app.delete("/mcp")
    async def delete_session(mcp_session_id: str | None = Header(default=None, alias="Mcp-Session-Id")) -> Response:
        if mcp_session_id:
            sessions.pop(mcp_session_id, None)
        return Response(status_code=204)

    @app.on_event("shutdown")
    async def shutdown() -> None:
        await transport.close()

    return app
