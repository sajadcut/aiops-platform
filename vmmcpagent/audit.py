"""Structured, secret-safe request/response audit for the Linux VM agent.

Log every application-level WebSocket request/response, not raw credentials,
config candidates, stdout/stderr or bearer headers. Those bodies can contain
passwords and production secrets. Preserve traceability through message ID,
field names, status, size and measured latency instead.
"""
from __future__ import annotations

import re
from typing import Any, Mapping
from uuid import uuid4

from domain.contracts.logging import logger

_SAFE = re.compile(r"[a-zA-Z0-9_.:@/-]{1,120}\Z")


def _safe_label(value: Any) -> str | None:
    return value if isinstance(value, str) and _SAFE.fullmatch(value) else None


def _safe_keys(value: Any) -> list[str]:
    if not isinstance(value, Mapping):
        return []
    return sorted(str(k)[:60] for k in value.keys())[:80]


def safe_frame(payload: Any) -> dict[str, Any]:
    """Only nonsecret metadata; never serialize raw wire contents."""
    if not isinstance(payload, Mapping):
        return {"body": "[OMITTED]", "format": type(payload).__name__}
    kind = _safe_label(payload.get("type")) or "unknown"
    result: dict[str, Any] = {"type": kind, "body": "[OMITTED]"}
    for key in ("id", "target", "tool"):
        value = _safe_label(payload.get(key))
        if value is not None:
            result[key] = value
    if kind == "credentials":
        result["credential_material"] = "[REDACTED]"
        result["username_present"] = isinstance(payload.get("username"), str)
    elif kind == "credentials_ack":
        result["ok"] = payload.get("ok") is True
    elif kind == "execute":
        args = payload.get("arguments")
        result["argument_fields"] = _safe_keys(args)
        if isinstance(args, Mapping):
            for key in ("service", "incident_id", "approval_id"):
                label = _safe_label(args.get(key))
                if label is not None:
                    result[key] = label
    elif kind == "result":
        response = payload.get("result")
        result["result_fields"] = _safe_keys(response)
        if isinstance(response, Mapping):
            result["success"] = response.get("success") is True
            for key in ("status", "execution_outcome"):
                label = _safe_label(response.get(key))
                if label:
                    result[key] = label
            code = response.get("exit_code")
            if type(code) is int:
                result["exit_code"] = code
    return result


def audit_frame(
    event: str, payload: Any, *, trace_id: str | None = None,
    duration_ms: float | None = None, byte_count: int | None = None,
    error_type: str | None = None,
) -> None:
    """Send one sanitized record through the configured text and JSON handlers."""
    details = {
        "component": "vmmcpagent",
        "trace_id": trace_id or _safe_label(payload.get("id")) if isinstance(payload, Mapping) else trace_id,
        "frame": safe_frame(payload),
    }
    if not details["trace_id"]:
        details["trace_id"] = "trc_" + uuid4().hex
    if duration_ms is not None:
        details["response_time_ms"] = round(float(duration_ms), 3)
    if byte_count is not None:
        details["bytes"] = int(byte_count)
    if error_type:
        details["error_type"] = type(error_type).__name__ if not isinstance(error_type, str) else (_safe_label(error_type) or "unknown")
    if error_type or (isinstance(payload, Mapping) and payload.get("type") == "result"
                      and isinstance(payload.get("result"), Mapping)
                      and payload["result"].get("success") is False):
        logger.warning(event, **details)
    else:
        logger.info(event, **details)
