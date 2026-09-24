"""Governed MCP Streamable-HTTP client used by external integrations."""
from __future__ import annotations

import asyncio
import itertools
import json
import time
from typing import Any, Dict, Iterable, Optional
from urllib.parse import urlparse

import httpx
from integrations.http_transport import insecure_async_client

from domain.contracts.config import settings
from domain.contracts.logging import log_workflow_step, logger
from domain.contracts.redaction import redact


_SAFE_REMOTE_POLICY_ERRORS = frozenset({
    "vm_target_not_allowed",
    "vm_service_not_allowed",
})


class MCPClient:
    production_supported = True
    _ids = itertools.count(1)

    def __init__(
        self,
        server_url: str,
        server_name: str,
        *,
        allowed_tools: Iterable[str],
        write_tools: Iterable[str] = (),
        protocol_version: str = "2025-03-26",
        timeout: float = 30.0,
        bearer_token: Optional[str] = None,
        write_bearer_token: Optional[str] = None,
        authorization_header: Optional[str] = None,
        write_authorization_header: Optional[str] = None,
        client_cert_path: Optional[str] = None,
        client_key_path: Optional[str] = None,
    ):
        self.server_url = str(server_url or "").strip()
        self.server_name = server_name
        self.allowed_tools = frozenset(str(x) for x in allowed_tools)
        self.write_tools = frozenset(str(x) for x in write_tools)
        if not self.write_tools <= self.allowed_tools:
            raise ValueError("mcp_write_tools_must_be_allowlisted")
        self.protocol_version = protocol_version
        self.negotiated_protocol_version = protocol_version
        self.timeout = float(timeout)
        self.bearer_token = bearer_token
        self.write_bearer_token = write_bearer_token
        self.authorization_header = str(authorization_header or "").strip() or None
        self.write_authorization_header = str(write_authorization_header or "").strip() or None
        self.session_id: Optional[str] = None
        self._initialized = False
        # Ordinary read operations use the shared bounded retry policy. Health
        # probes may temporarily override this to one attempt so readiness
        # checks do not amplify an unavailable dependency into repeated traffic.
        self.read_retry_attempts_override: Optional[int] = None

        parsed = urlparse(self.server_url)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise ValueError(f"invalid_mcp_server_url:{server_name}")
        if bool(client_cert_path) != bool(client_key_path):
            raise ValueError("mcp_client_cert_and_key_must_be_configured_together")

        cert = (client_cert_path, client_key_path) if client_cert_path and client_key_path else None
        self._client = insecure_async_client(timeout=self.timeout, cert=cert, component=f"mcp:{self.server_name}")

    def _authorization(self, tool_name: Optional[str]) -> Optional[str]:
        if tool_name in self.write_tools:
            if self.write_authorization_header:
                return self.write_authorization_header
            if self.write_bearer_token:
                return f"Bearer {self.write_bearer_token}"
            raise PermissionError(f"mcp_write_identity_required:{self.server_name}:{tool_name}")
        if self.authorization_header:
            return self.authorization_header
        if self.bearer_token:
            return f"Bearer {self.bearer_token}"
        return None

    def _headers(self, *, tool_name: Optional[str] = None, include_protocol: bool = True) -> Dict[str, str]:
        headers = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream"}
        if include_protocol:
            headers["MCP-Protocol-Version"] = self.negotiated_protocol_version
        if self.session_id:
            headers["Mcp-Session-Id"] = self.session_id
        authorization = self._authorization(tool_name)
        if authorization:
            headers["Authorization"] = authorization
        return headers

    @staticmethod
    def _decode_response(response: httpx.Response) -> Dict[str, Any]:
        if response.status_code == 202 or not response.content:
            return {}
        content_type = response.headers.get("content-type", "").lower()
        if "text/event-stream" not in content_type:
            data = response.json()
            return data if isinstance(data, dict) else {}
        last: Dict[str, Any] = {}
        for line in response.text.splitlines():
            if not line.startswith("data:"):
                continue
            payload = line[5:].strip()
            if not payload or payload == "[DONE]":
                continue
            try:
                decoded = json.loads(payload)
            except json.JSONDecodeError:
                continue
            if isinstance(decoded, dict):
                last = decoded
                if "result" in decoded or "error" in decoded:
                    return decoded
        return last

    @staticmethod
    def _bounded_for_log(value: Any) -> Any:
        safe = redact(value)
        try:
            encoded = json.dumps(safe, ensure_ascii=False, default=str).encode("utf-8")
        except Exception:
            return {"omitted": "unserializable"}
        if len(encoded) > settings.LOG_HTTP_BODY_MAX_BYTES:
            return {"omitted": "payload_too_large", "size_bytes": len(encoded)}
        return safe

    @staticmethod
    def _incident_id_from_payload(payload: Dict[str, Any]) -> Optional[str]:
        params = payload.get("params")
        if not isinstance(params, dict):
            return None
        arguments = params.get("arguments")
        candidates = [params]
        if isinstance(arguments, dict):
            candidates.insert(0, arguments)
        for candidate in candidates:
            for key in ("incident_id", "incidentId"):
                value = candidate.get(key)
                if value:
                    return str(value)
        return None

    async def _post(self, payload: Dict[str, Any], *, tool_name: Optional[str] = None, include_protocol: bool = True) -> Dict[str, Any]:
        # Writes are intentionally never retried: a lost response after a remote
        # side effect is ambiguous until the remote protocol supports a durable
        # idempotency key. Read/initialize/list calls may retry transport/5xx.
        configured_read_attempts = (
            settings.RETRY_MAX_ATTEMPTS
            if self.read_retry_attempts_override is None
            else self.read_retry_attempts_override
        )
        attempts = 1 if tool_name in self.write_tools else max(1, int(configured_read_attempts))
        delay = max(0.0, float(settings.RETRY_DELAY_SECONDS))
        method = str(payload.get("method") or "unknown")
        incident_id = self._incident_id_from_payload(payload)
        timeline_stage = "execution" if tool_name in self.write_tools else "live_evidence"
        timeline_action = str(tool_name or method)
        for attempt in range(1, attempts + 1):
            started = time.perf_counter()
            logger.info(
                "mcp_request",
                server=self.server_name,
                method=method,
                tool=tool_name,
                attempt=attempt,
                request=self._bounded_for_log(payload),
            )
            log_workflow_step(
                incident_id=incident_id,
                stage=timeline_stage,
                component=f"mcp:{self.server_name}",
                action=timeline_action,
                status="started",
                summary=f"MCP {self.server_name} call started: {timeline_action}",
                details={"method": method, "tool": tool_name, "attempt": attempt},
            )
            try:
                response = await self._client.post(
                    self.server_url,
                    json=payload,
                    headers=self._headers(tool_name=tool_name, include_protocol=include_protocol),
                )
                if response.status_code >= 500 and attempt < attempts:
                    duration_ms = round((time.perf_counter() - started) * 1000, 3)
                    logger.warning(
                        "mcp_response_retryable",
                        server=self.server_name,
                        method=method,
                        tool=tool_name,
                        status=response.status_code,
                        duration_ms=duration_ms,
                    )
                    log_workflow_step(
                        incident_id=incident_id,
                        stage=timeline_stage,
                        component=f"mcp:{self.server_name}",
                        action=timeline_action,
                        status="retrying",
                        summary=f"MCP {self.server_name} call will retry",
                        details={"http_status": response.status_code, "attempt": attempt, "duration_ms": duration_ms},
                        level="warning",
                    )
                    await asyncio.sleep(delay)
                    delay *= max(1.0, float(settings.RETRY_BACKOFF_FACTOR))
                    continue
                response.raise_for_status()
                if response.headers.get("Mcp-Session-Id"):
                    self.session_id = response.headers["Mcp-Session-Id"]
                decoded = self._decode_response(response)
                duration_ms = round((time.perf_counter() - started) * 1000, 3)
                logger.info(
                    "mcp_response",
                    server=self.server_name,
                    method=method,
                    tool=tool_name,
                    status=response.status_code,
                    duration_ms=duration_ms,
                    response=self._bounded_for_log(decoded),
                )
                tool_result = decoded.get("result")
                tool_failed = (
                    method == "tools/call"
                    and isinstance(tool_result, dict)
                    and tool_result.get("isError") is True
                )
                if tool_failed:
                    logger.warning(
                        "mcp_tool_error_response",
                        server=self.server_name,
                        tool=tool_name,
                        status=response.status_code,
                        response=self._bounded_for_log(tool_result),
                    )
                    log_workflow_step(
                        incident_id=incident_id,
                        stage=timeline_stage,
                        component=f"mcp:{self.server_name}",
                        action=timeline_action,
                        status="failed",
                        summary=f"MCP {self.server_name} tool failed: {timeline_action}",
                        details={"http_status": response.status_code, "attempt": attempt, "duration_ms": duration_ms},
                        level="warning",
                    )
                else:
                    log_workflow_step(
                        incident_id=incident_id,
                        stage=timeline_stage,
                        component=f"mcp:{self.server_name}",
                        action=timeline_action,
                        status="completed",
                        summary=f"MCP {self.server_name} call completed: {timeline_action}",
                        details={"http_status": response.status_code, "attempt": attempt, "duration_ms": duration_ms},
                    )
                return decoded
            except PermissionError:
                log_workflow_step(
                    incident_id=incident_id,
                    stage=timeline_stage,
                    component=f"mcp:{self.server_name}",
                    action=timeline_action,
                    status="blocked",
                    summary=f"MCP {self.server_name} call blocked by authorization policy",
                    details={"attempt": attempt},
                    level="warning",
                )
                raise
            except (httpx.TimeoutException, httpx.TransportError) as exc:
                duration_ms = round((time.perf_counter() - started) * 1000, 3)
                logger.warning(
                    "mcp_transport_failure",
                    server=self.server_name,
                    method=method,
                    tool=tool_name,
                    attempt=attempt,
                    error_type=type(exc).__name__,
                    duration_ms=duration_ms,
                )
                if attempt < attempts:
                    log_workflow_step(
                        incident_id=incident_id,
                        stage=timeline_stage,
                        component=f"mcp:{self.server_name}",
                        action=timeline_action,
                        status="retrying",
                        summary=f"MCP {self.server_name} transport failure; retrying",
                        details={"error_type": type(exc).__name__, "attempt": attempt, "duration_ms": duration_ms},
                        level="warning",
                    )
                    await asyncio.sleep(delay)
                    delay *= max(1.0, float(settings.RETRY_BACKOFF_FACTOR))
                    continue
                log_workflow_step(
                    incident_id=incident_id,
                    stage=timeline_stage,
                    component=f"mcp:{self.server_name}",
                    action=timeline_action,
                    status="failed",
                    summary=f"MCP {self.server_name} transport call failed",
                    details={"error_type": type(exc).__name__, "attempt": attempt, "duration_ms": duration_ms},
                    level="warning",
                )
                raise RuntimeError(f"mcp_transport_error:{self.server_name}") from exc
            except httpx.HTTPStatusError as exc:
                duration_ms = round((time.perf_counter() - started) * 1000, 3)
                logger.warning(
                    "mcp_http_error",
                    server=self.server_name,
                    method=method,
                    tool=tool_name,
                    status=exc.response.status_code,
                    duration_ms=duration_ms,
                )
                log_workflow_step(
                    incident_id=incident_id,
                    stage=timeline_stage,
                    component=f"mcp:{self.server_name}",
                    action=timeline_action,
                    status="failed",
                    summary=f"MCP {self.server_name} returned an HTTP error",
                    details={"http_status": exc.response.status_code, "duration_ms": duration_ms},
                    level="warning",
                )
                raise RuntimeError(f"mcp_http_error:{self.server_name}") from exc
            except Exception as exc:
                logger.exception(
                    "mcp_request_failed",
                    server=self.server_name,
                    method=method,
                    tool=tool_name,
                    error_type=type(exc).__name__,
                )
                log_workflow_step(
                    incident_id=incident_id,
                    stage=timeline_stage,
                    component=f"mcp:{self.server_name}",
                    action=timeline_action,
                    status="failed",
                    summary=f"MCP {self.server_name} call failed",
                    details={"error_type": type(exc).__name__, "attempt": attempt},
                    level="warning",
                )
                raise RuntimeError(f"mcp_transport_error:{self.server_name}") from exc
        raise RuntimeError(f"mcp_transport_error:{self.server_name}")

    async def initialize(self) -> Dict[str, Any]:
        if self._initialized:
            return {"protocolVersion": self.negotiated_protocol_version}
        result = await self._post(
            {
                "jsonrpc": "2.0",
                "id": next(self._ids),
                "method": "initialize",
                "params": {
                    "protocolVersion": self.protocol_version,
                    "capabilities": {},
                    "clientInfo": {"name": "aiops-platform", "version": settings.APP_VERSION},
                },
            },
            include_protocol=False,
        )
        if result.get("error"):
            logger.warning("mcp_initialize_rejected", server=self.server_name, response=self._bounded_for_log(result))
            raise RuntimeError(f"mcp_initialize_error:{self.server_name}")
        init_result = result.get("result") or {}
        negotiated = init_result.get("protocolVersion")
        if negotiated:
            self.negotiated_protocol_version = str(negotiated)
        await self._post({"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}}, include_protocol=True)
        self._initialized = True
        return init_result

    async def _request(self, method: str, params: Dict[str, Any], *, tool_name: Optional[str] = None) -> Dict[str, Any]:
        await self.initialize()
        result = await self._post(
            {"jsonrpc": "2.0", "method": method, "params": params, "id": next(self._ids)},
            tool_name=tool_name,
        )
        if result.get("error"):
            logger.warning("mcp_remote_error", server=self.server_name, method=method, tool=tool_name, response=self._bounded_for_log(result))
            remote_error = result.get("error")
            remote_message = (
                str(remote_error.get("message") or "").strip()
                if isinstance(remote_error, dict)
                else ""
            )
            # Preserve only explicit, locally allowlisted policy denials. Never
            # propagate arbitrary remote error text into higher layers or UI.
            if remote_message in _SAFE_REMOTE_POLICY_ERRORS:
                raise PermissionError(remote_message)
            raise RuntimeError(f"mcp_remote_error:{self.server_name}")
        payload = result.get("result", {})
        if method == "tools/call" and isinstance(payload, dict) and payload.get("isError") is True:
            logger.warning(
                "mcp_tool_error",
                server=self.server_name,
                tool=tool_name,
                response=self._bounded_for_log(payload),
            )
            raise RuntimeError(f"mcp_tool_error:{self.server_name}:{tool_name or 'unknown'}")
        return payload if isinstance(payload, dict) else {}

    async def call_tool(self, tool_name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        if tool_name not in self.allowed_tools:
            raise PermissionError(f"mcp_tool_not_allowed:{self.server_name}:{tool_name}")
        return await self._request("tools/call", {"name": tool_name, "arguments": arguments}, tool_name=tool_name)

    async def _call_tool(self, tool_name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        return await self.call_tool(tool_name, arguments)

    async def list_tools(self) -> list:
        result = await self._request("tools/list", {})
        tools = result.get("tools", [])
        return [tool for tool in tools if isinstance(tool, dict) and tool.get("name") in self.allowed_tools]

    @staticmethod
    def json_content(result: Dict[str, Any]) -> list[Any]:
        structured = result.get("structuredContent")
        if isinstance(structured, list):
            return structured
        if isinstance(structured, dict):
            return [structured]
        extracted: list[Any] = []
        for part in result.get("content", []) or []:
            if isinstance(part, list):
                extracted.extend(part)
                continue
            if not isinstance(part, dict):
                continue
            if "json" in part and isinstance(part["json"], (dict, list)):
                value = part["json"]
            elif part.get("type") == "text" and isinstance(part.get("text"), str):
                try:
                    value = json.loads(part["text"])
                except json.JSONDecodeError:
                    continue
            elif part.get("type") is None:
                value = part
            else:
                continue
            extracted.extend(value if isinstance(value, list) else [value])
        return extracted

    async def health_check(self) -> bool:
        try:
            await self.list_tools()
            return True
        except Exception:
            return False

    async def close(self) -> None:
        if self.session_id:
            try:
                await self._client.delete(self.server_url, headers=self._headers())
            except Exception as exc:
                logger.debug("mcp_session_close_failed", server=self.server_name, error_type=type(exc).__name__)
        await self._client.aclose()
