from __future__ import annotations

import json
import time
from typing import Any, Awaitable, Callable
from uuid import uuid4

from domain.contracts.config import settings
from domain.contracts.logging import logger, redact_value
from domain.contracts.metrics import HTTP_IN_FLIGHT, observe_http

ASGIApp = Callable[[dict[str, Any], Callable[[], Awaitable[dict[str, Any]]], Callable[[dict[str, Any]], Awaitable[None]]], Awaitable[None]]
_SAFE_BODY_TYPES = ("application/json", "application/problem+json", "text/")
_CONTEXT_KEYS = ("incident_id", "approval_id", "execution_id", "action", "target")


def _header_map(headers: list[tuple[bytes, bytes]]) -> dict[str, str]:
    result: dict[str, str] = {}
    for raw_key, raw_value in headers:
        try:
            result[raw_key.decode("latin-1").lower()] = raw_value.decode("latin-1")
        except Exception:
            continue
    return result


def _bounded_identifier(value: str | None) -> str | None:
    if not value:
        return None
    cleaned = value.strip()
    if not cleaned or len(cleaned) > 128 or any(ord(ch) < 32 for ch in cleaned):
        return None
    return cleaned


def _body_allowed(content_type: str | None, content_length: str | None) -> bool:
    if not settings.LOG_HTTP_BODY_ENABLED:
        return False
    normalized = str(content_type or "").split(";", 1)[0].strip().lower()
    if not any(normalized == allowed or (allowed.endswith("/") and normalized.startswith(allowed)) for allowed in _SAFE_BODY_TYPES):
        return False
    if content_length:
        try:
            if int(content_length) > settings.LOG_HTTP_BODY_MAX_BYTES:
                return False
        except ValueError:
            return False
    return True


def _decode_body(raw: bytes) -> Any:
    if not raw:
        return None
    text = raw.decode("utf-8", errors="replace")
    try:
        return redact_value(json.loads(text))
    except json.JSONDecodeError:
        return redact_value(text)


def _operational_context(payload: Any) -> dict[str, Any]:
    if not isinstance(payload, dict):
        return {}
    result: dict[str, Any] = {}
    for key in _CONTEXT_KEYS:
        if payload.get(key) is not None:
            result[key] = str(payload[key])
    tool = payload.get("tool_name", payload.get("tool"))
    if tool is not None:
        result["tool"] = str(tool)
    nested = payload.get("execution_request")
    if isinstance(nested, dict):
        for key, value in _operational_context(nested).items():
            result.setdefault(key, value)
    return result


class RequestLoggingMiddleware:
    """ASGI middleware for correlation, bounded body capture, metrics, and structured request logs."""

    def __init__(self, app: ASGIApp):
        self.app = app

    async def __call__(self, scope, receive, send) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return

        started = time.perf_counter()
        HTTP_IN_FLIGHT.inc()
        headers = _header_map(list(scope.get("headers") or []))
        request_id = _bounded_identifier(headers.get("x-request-id")) or str(uuid4())
        correlation_id = _bounded_identifier(headers.get("x-correlation-id")) or request_id
        state = scope.setdefault("state", {})
        state["request_id"] = request_id
        state["correlation_id"] = correlation_id

        request_capture = bytearray()
        response_capture = bytearray()
        request_capture_enabled = _body_allowed(headers.get("content-type"), headers.get("content-length"))
        response_capture_enabled = False
        request_truncated = False
        response_truncated = False
        response_status = 500

        async def wrapped_receive():
            nonlocal request_truncated
            message = await receive()
            if request_capture_enabled and message.get("type") == "http.request":
                chunk = message.get("body", b"") or b""
                remaining = settings.LOG_HTTP_BODY_MAX_BYTES - len(request_capture)
                if remaining > 0:
                    request_capture.extend(chunk[:remaining])
                if len(chunk) > remaining or message.get("more_body", False) and len(request_capture) >= settings.LOG_HTTP_BODY_MAX_BYTES:
                    request_truncated = True
            return message

        async def wrapped_send(message):
            nonlocal response_status, response_capture_enabled, response_truncated
            if message.get("type") == "http.response.start":
                response_status = int(message.get("status", 500))
                raw_headers = list(message.get("headers") or [])
                response_headers = _header_map(raw_headers)
                response_capture_enabled = _body_allowed(response_headers.get("content-type"), response_headers.get("content-length"))
                lower_names = {key.lower() for key in response_headers}
                if "x-request-id" not in lower_names:
                    raw_headers.append((b"x-request-id", request_id.encode("ascii", errors="ignore")))
                if "x-correlation-id" not in lower_names:
                    raw_headers.append((b"x-correlation-id", correlation_id.encode("ascii", errors="ignore")))
                message["headers"] = raw_headers
            elif response_capture_enabled and message.get("type") == "http.response.body":
                chunk = message.get("body", b"") or b""
                remaining = settings.LOG_HTTP_BODY_MAX_BYTES - len(response_capture)
                if remaining > 0:
                    response_capture.extend(chunk[:remaining])
                if len(chunk) > remaining or message.get("more_body", False) and len(response_capture) >= settings.LOG_HTTP_BODY_MAX_BYTES:
                    response_truncated = True
            await send(message)

        try:
            await self.app(scope, wrapped_receive, wrapped_send)
        finally:
            duration_seconds = max(time.perf_counter() - started, 0.0)
            route_template = getattr(scope.get("route"), "path", None) or scope.get("path") or "unknown"
            observe_http(str(scope.get("method") or "UNKNOWN"), str(route_template), response_status, duration_seconds)
            HTTP_IN_FLIGHT.dec()

            request_body = _decode_body(bytes(request_capture)) if request_capture else None
            response_body = _decode_body(bytes(response_capture)) if response_capture else None
            context = _operational_context(request_body)
            for key, value in _operational_context(response_body).items():
                context.setdefault(key, value)
            path_params = scope.get("path_params") or {}
            for key in ("incident_id", "approval_id", "execution_id"):
                if key not in context and path_params.get(key) is not None:
                    context[key] = str(path_params[key])

            event: dict[str, Any] = {
                "request_id": request_id,
                "correlation_id": correlation_id,
                "method": scope.get("method"),
                "path": scope.get("path"),
                "route": route_template,
                "status": response_status,
                "duration_ms": round(duration_seconds * 1000, 3),
                "identity": state.get("identity_subject"),
                "roles": state.get("identity_roles"),
                **context,
            }
            if request_body is not None:
                event["request_body"] = request_body
                event["request_body_truncated"] = request_truncated
            if response_body is not None:
                event["response_body"] = response_body
                event["response_body_truncated"] = response_truncated
            logger.info("http_request_completed", **event)
