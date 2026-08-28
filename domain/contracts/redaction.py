from __future__ import annotations

import re
from typing import Any, Mapping

REDACTED = "[REDACTED]"

# Normalize '-' to '_' before matching so Authorization/X-API-Key/Cookie style
# headers and JSON field names go through the same policy.
_SENSITIVE_KEY_TERMS = (
    "authorization",
    "api_key",
    "apikey",
    "password",
    "passwd",
    "secret",
    "token",
    "private_key",
    "client_secret",
    "cookie",
    "set_cookie",
    "credential",
    "database_url",
    "alembic_database_url",
    "dsn",
)

_BEARER = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]+")
_BASIC = re.compile(r"(?i)\bBasic\s+[A-Za-z0-9+/=]+")
_DSN_CREDENTIAL = re.compile(r"(?P<scheme>[a-zA-Z][a-zA-Z0-9+.-]*://)(?P<userinfo>[^/@\s:]+:[^/@\s]+)@")
_PRIVATE_KEY = re.compile(
    r"-----BEGIN [^-\n]*PRIVATE KEY-----.*?-----END [^-\n]*PRIVATE KEY-----",
    re.DOTALL,
)


def is_sensitive_key(key: str | None) -> bool:
    normalized = str(key or "").strip().lower().replace("-", "_")
    return any(term in normalized for term in _SENSITIVE_KEY_TERMS)


def redact_text(value: str) -> str:
    text = str(value)
    text = _PRIVATE_KEY.sub(REDACTED, text)
    text = _BEARER.sub(f"Bearer {REDACTED}", text)
    text = _BASIC.sub(f"Basic {REDACTED}", text)
    text = _DSN_CREDENTIAL.sub(lambda m: f"{m.group('scheme')}{REDACTED}@", text)
    return text


def redact(value: Any, key: str | None = None) -> Any:
    """Recursively redact credentials from structured and free-form values."""
    if is_sensitive_key(key):
        return REDACTED
    if isinstance(value, Mapping):
        return {str(k): redact(v, str(k)) for k, v in value.items()}
    if isinstance(value, list):
        return [redact(item) for item in value]
    if isinstance(value, tuple):
        return tuple(redact(item) for item in value)
    if isinstance(value, str):
        return redact_text(value)
    return value


def redact_event_dict(_logger: Any, _method_name: str, event_dict: dict[str, Any]) -> dict[str, Any]:
    """structlog processor: scrub the final event, including rendered traceback text."""
    return redact(event_dict)
