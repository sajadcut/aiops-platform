from __future__ import annotations

import json
import time
from typing import Any, Awaitable, Callable
from uuid import uuid4

from domain.contracts.config import settings
from domain.contracts.context import set_trace_id
from domain.contracts.logging import logger
from domain.contracts.redaction import redact
from domain.observability import HTTP_REQUESTS_IN_PROGRESS, observe_http

ASGIApp = Callable[[dict[str, Any], Callable[[], Awaitable[dict[str, Any]]], Callable[[dict[str, Any]], Awaitable[None]]], Awaitable[None]]


def _headers(scope: dict[str, Any]) -> dict[str, str]:
    return {
        key.decode("latin1").lower(): value.decode("latin1")
        for key, value in scope.get("headers", [])
    }


def _safe_json_body(raw: bytes, content_type: str, *, enabled: bool) -> Any:
    if not enabled or not raw:
        return None
    if len(raw) > settings.LOG_HTTP_BODY_MAX_BYTES:
        return {"omitted": "body_too_large", "size_bytes": len(raw)}
    if "json" not in str(content_type or "").lower():
        return {"omitted": "non_json_body", "size_bytes": len(raw)}
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return {"omitted": "invalid_json_body", "size_bytes": len(raw)}
    return redact(value)


def _value(body: Any, *names: str) -> Any:
    if not isinstance(body, dict):
        return None
    for name in names:
        value = body.get(name)
        if value not in (None, ""):
            return value
    return None


class HTTPTransactionLoggingMiddleware:
    """Persist one redacted, correlated event for every HTTP transaction."""

    def __init__(self, app: ASGIApp):
        self.app = app

    async def __call__(self, scope: dict[str, Any], receive, send) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return

        incoming_headers = _headers(scope)
        request_id = incoming_headers.get("x-request-id") or str(uuid4())
        correlation_id = incoming_headers.get("x-correlation-id") or incoming_headers.get("x-trace-id") or request_id
        path = str(scope.get("path") or "")
        execution_id = incoming_headers.get("x-execution-id")
        if not execution_id and (path.endswith("/execute") or "/execute/" in path):
            execution_id = str(uuid4())

        state = scope.setdefault("state", {})
        state["request_id"] = request_id
        state["correlation_id"] = correlation_id
        if execution_id:
            state["execution_id"] = execution_id
        set_trace_id(correlation_id)

        request_body = bytearray()
        response_body = bytearray()
        response_content_type = ""
        status_code = 500
        started = time.perf_counter()
        HTTP_REQUESTS_IN_PROGRESS.inc()

        async def logging_receive() -> dict[str, Any]:
            message = await receive()
            if message.get("type") == "http.request":
                chunk = message.get("body", b"") or b""
                if len(request_body) <= settings.LOG_HTTP_BODY_MAX_BYTES:
                    request_body.extend(chunk[: settings.LOG_HTTP_BODY_MAX_BYTES + 1 - len(request_body)])
            return message

        async def logging_send(message: dict[str, Any]) -> None:
            nonlocal status_code, response_content_type
            if message.get("type") == "http.response.start":
                status_code = int(message.get("status", 500))
                headers = list(message.get("headers", []))
                for key, value in headers:
                    if key.lower() == b"content-type":
                        response_content_type = value.decode("latin1")
                headers.append((b"x-request-id", request_id.encode("ascii", errors="ignore")))
                headers.append((b"x-correlation-id", correlation_id.encode("ascii", errors="ignore")))
                if execution_id:
                    headers.append((b"x-execution-id", execution_id.encode("ascii", errors="ignore")))
                message = {**message, "headers": headers}
            elif message.get("type") == "http.response.body":
                chunk = message.get("body", b"") or b""
                if len(response_body) <= settings.LOG_HTTP_BODY_MAX_BYTES:
                    response_body.extend(chunk[: settings.LOG_HTTP_BODY_MAX_BYTES + 1 - len(response_body)])
            await send(message)

        raised: BaseException | None = None
        try:
            await self.app(scope, logging_receive, logging_send)
        except BaseException as exc:
            raised = exc
            raise
        finally:
            HTTP_REQUESTS_IN_PROGRESS.dec()
            duration_seconds = time.perf_counter() - started
            duration_ms = round(duration_seconds * 1000, 3)
            request_payload = _safe_json_body(bytes(request_body), incoming_headers.get("content-type", ""), enabled=settings.LOG_HTTP_BODY_ENABLED)
            response_payload = _safe_json_body(bytes(response_body), response_content_type, enabled=settings.LOG_HTTP_BODY_ENABLED)
            route = getattr(scope.get("route"), "path", None) or path
            path_params = scope.get("path_params") or {}
            identity = state.get("identity_subject")

            incident_id = path_params.get("incident_id") or _value(request_payload, "incident_id")
            approval_id = path_params.get("approval_id") or _value(request_payload, "approval_id")
            tool = _value(request_payload, "tool_name", "tool")
            action = _value(request_payload, "action")
            target = _value(request_payload, "target")

            event: dict[str, Any] = {
                "request_id": request_id,
                "correlation_id": correlation_id,
                "execution_id": execution_id,
                "method": scope.get("method"),
                "path": path,
                "route": route,
                "status": status_code,
                "duration_ms": duration_ms,
                "identity": identity,
                "roles": state.get("identity_roles"),
                "incident_id": incident_id,
                "approval_id": approval_id,
                "tool": tool,
                "action": action,
                "target": target,
                "request_body": request_payload,
                "response_body": response_payload,
            }
            if raised is not None:
                event["error_type"] = type(raised).__name__
            logger.info("http_transaction", **redact(event))
            observe_http(str(scope.get("method") or "UNKNOWN"), str(route), status_code, duration_seconds)
