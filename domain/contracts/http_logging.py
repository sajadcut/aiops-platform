from __future__ import annotations

import json
import re
import time
from typing import Any, Iterable
from urllib.parse import parse_qsl, urlencode

from domain.contracts.context import generate_trace_id, set_trace_id
from domain.contracts.logging import logger

_SENSITIVE_TERMS = (
    "password", "passwd", "secret", "token", "authorization", "api_key", "apikey",
    "x_api_key", "private_key", "client_secret", "cookie", "set_cookie", "credential",
)
_BEARER_RE = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]+")
_REQUEST_ID_RE = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
_TEXTUAL_TYPES = (
    "application/json",
    "application/problem+json",
    "application/x-www-form-urlencoded",
    "text/",
)


def _sensitive_key(key: str) -> bool:
    normalized = str(key or "").lower().replace("-", "_")
    return any(term in normalized for term in _SENSITIVE_TERMS)


def _scrub_text(value: str) -> str:
    text = _BEARER_RE.sub("Bearer [REDACTED]", str(value))
    return text


def sanitize(value: Any, key: str | None = None) -> Any:
    """Recursively redact common credential fields before anything reaches logs."""
    if key is not None and _sensitive_key(key):
        return "[REDACTED]"
    if isinstance(value, dict):
        return {str(k): sanitize(v, str(k)) for k, v in value.items()}
    if isinstance(value, list):
        return [sanitize(item) for item in value]
    if isinstance(value, tuple):
        return tuple(sanitize(item) for item in value)
    if isinstance(value, str):
        return _scrub_text(value)
    return value


def sanitize_headers(headers: Iterable[tuple[bytes, bytes]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for raw_key, raw_value in headers:
        key = raw_key.decode("latin-1", errors="replace")
        value = raw_value.decode("latin-1", errors="replace")
        result[key] = sanitize(value, key)
    return result


def sanitize_query_string(raw_query: bytes) -> str:
    if not raw_query:
        return ""
    text = raw_query.decode("utf-8", errors="replace")
    try:
        pairs = parse_qsl(text, keep_blank_values=True)
        return urlencode([(key, "[REDACTED]" if _sensitive_key(key) else _scrub_text(value)) for key, value in pairs])
    except Exception:
        return _scrub_text(text)


def _is_textual(content_type: str) -> bool:
    lowered = str(content_type or "").lower()
    return any(token in lowered for token in _TEXTUAL_TYPES)


def _decode_body(body: bytes, content_type: str, truncated: bool) -> Any:
    if not body:
        return None
    if not _is_textual(content_type):
        return {"logged": False, "reason": "non_text_body", "bytes": len(body)}
    text = body.decode("utf-8", errors="replace")
    value: Any = text
    if "json" in content_type.lower():
        try:
            value = json.loads(text)
        except json.JSONDecodeError:
            value = text
    sanitized = sanitize(value)
    if truncated:
        return {"truncated": True, "value": sanitized}
    return sanitized


def _extract_context_ids(*values: Any) -> dict[str, str]:
    wanted = {"incident_id", "approval_id", "execution_id", "workflow_id"}
    found: dict[str, str] = {}

    def walk(value: Any) -> None:
        if isinstance(value, dict):
            for key, item in value.items():
                normalized = str(key).lower()
                if normalized in wanted and item is not None and normalized not in found:
                    found[normalized] = str(item)[:128]
                if len(found) < len(wanted):
                    walk(item)
        elif isinstance(value, list):
            for item in value[:20]:
                walk(item)

    for value in values:
        walk(value)
    return found


class RequestResponseLoggingMiddleware:
    """ASGI middleware that logs bounded, sanitized HTTP request/response evidence.

    It never changes request bodies, supports streaming responses, propagates a safe
    request id as ``X-Request-ID`` and binds the same id into the existing trace
    context. Body capture is bounded and binary/multipart content is not emitted.
    """

    def __init__(self, app, *, enabled: bool = True, body_max_bytes: int = 32768, log_headers: bool = True):
        self.app = app
        self.enabled = bool(enabled)
        self.body_max_bytes = max(1024, int(body_max_bytes))
        self.log_headers = bool(log_headers)

    async def __call__(self, scope, receive, send) -> None:
        if scope.get("type") != "http" or not self.enabled:
            await self.app(scope, receive, send)
            return

        incoming_headers = list(scope.get("headers") or [])
        decoded_headers = sanitize_headers(incoming_headers)
        raw_request_id = next(
            (
                value.decode("latin-1", errors="replace")
                for key, value in incoming_headers
                if key.lower() == b"x-request-id"
            ),
            "",
        )
        request_id = raw_request_id if _REQUEST_ID_RE.fullmatch(raw_request_id) else generate_trace_id()
        set_trace_id(request_id)

        request_body = bytearray()
        request_truncated = False
        response_body = bytearray()
        response_truncated = False
        response_status = 500
        response_headers: list[tuple[bytes, bytes]] = []
        started = time.perf_counter()

        async def logged_receive():
            nonlocal request_truncated
            message = await receive()
            if message.get("type") == "http.request":
                chunk = message.get("body", b"") or b""
                remaining = self.body_max_bytes - len(request_body)
                if remaining > 0:
                    request_body.extend(chunk[:remaining])
                if len(chunk) > max(remaining, 0):
                    request_truncated = True
            return message

        async def logged_send(message):
            nonlocal response_status, response_headers, response_truncated
            if message.get("type") == "http.response.start":
                response_status = int(message.get("status", 500))
                headers = list(message.get("headers") or [])
                if not any(key.lower() == b"x-request-id" for key, _ in headers):
                    headers.append((b"x-request-id", request_id.encode("ascii", errors="ignore")))
                    message = {**message, "headers": headers}
                response_headers = headers
            elif message.get("type") == "http.response.body":
                chunk = message.get("body", b"") or b""
                remaining = self.body_max_bytes - len(response_body)
                if remaining > 0:
                    response_body.extend(chunk[:remaining])
                if len(chunk) > max(remaining, 0):
                    response_truncated = True
            await send(message)

        failure: str | None = None
        try:
            await self.app(scope, logged_receive, logged_send)
        except Exception as exc:
            failure = type(exc).__name__
            raise
        finally:
            duration_ms = round((time.perf_counter() - started) * 1000, 3)
            request_content_type = str(decoded_headers.get("content-type") or "")
            sanitized_response_headers = sanitize_headers(response_headers)
            response_content_type = str(sanitized_response_headers.get("content-type") or "")
            decoded_request = _decode_body(bytes(request_body), request_content_type, request_truncated)
            decoded_response = _decode_body(bytes(response_body), response_content_type, response_truncated)
            context_ids = _extract_context_ids(decoded_request, decoded_response)
            logger.info(
                "http_request_completed",
                request_id=request_id,
                trace_id=request_id,
                method=scope.get("method"),
                path=scope.get("path"),
                query=sanitize_query_string(scope.get("query_string", b"")),
                status_code=response_status,
                duration_ms=duration_ms,
                request_headers=decoded_headers if self.log_headers else None,
                response_headers=sanitized_response_headers if self.log_headers else None,
                request_body=decoded_request,
                response_body=decoded_response,
                request_body_truncated=request_truncated,
                response_body_truncated=response_truncated,
                failure=failure,
                **context_ids,
            )
