from __future__ import annotations

import re
from typing import Any, Dict, Iterable, List, Mapping


_SENSITIVE_KEY_TOKENS = (
    "authorization", "password", "passwd", "secret", "token", "private_key", "privatekey",
    "access_token", "refresh_token", "id_token", "client_secret", "api_key", "apikey",
    "credential", "cookie", "set-cookie", "token_value", "secret_value",
)

_ASSIGNMENT_PATTERN = re.compile(
    r"(?i)\b(password|passwd|secret|token|access_token|refresh_token|id_token|api[_-]?key|client_secret)\s*[:=]\s*([^\s,;]+)"
)
_BEARER_PATTERN = re.compile(r"(?i)bearer\s+[A-Za-z0-9._~+/=-]+")
_JWT_PATTERN = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")


def _sensitive_key(key: Any) -> bool:
    normalized = str(key).strip().lower().replace("-", "_")
    return any(token in normalized for token in _SENSITIVE_KEY_TOKENS)


def redact_security_value(value: Any, depth: int = 0) -> Any:
    """Bound operational security context and remove credential material.

    Security analysis may reason about token/secret *usage metadata*, but values are
    not part of the diagnostic contract and must not be sent to the model.
    """
    if depth >= 5:
        return "[bounded]"
    if isinstance(value, str):
        text = _BEARER_PATTERN.sub("Bearer [REDACTED]", value)
        text = _JWT_PATTERN.sub("[REDACTED_JWT]", text)
        text = _ASSIGNMENT_PATTERN.sub(lambda match: f"{match.group(1)}=[REDACTED]", text)
        return text if len(text) <= 520 else text[:520] + "...[truncated]"
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    if isinstance(value, (list, tuple)):
        return [redact_security_value(item, depth + 1) for item in list(value)[:12]]
    if isinstance(value, Mapping):
        result: Dict[str, Any] = {}
        for key, current in list(value.items())[:50]:
            result[str(key)] = "[REDACTED]" if _sensitive_key(key) else redact_security_value(current, depth + 1)
        return result
    return redact_security_value(str(value), depth + 1)


def security_prompt_evidence(evidence: Iterable[Mapping[str, Any]], limit: int = 40) -> List[Dict[str, Any]]:
    projected: List[Dict[str, Any]] = []
    for item in list(evidence)[:limit]:
        if not isinstance(item, Mapping):
            continue
        projected.append(redact_security_value({
            "id": item.get("evidence_id") or item.get("id") or item.get("reference"),
            "type": item.get("type"),
            "source": item.get("source"),
            "timestamp": item.get("observed_at") or item.get("timestamp") or item.get("created_at"),
            "name": item.get("name"),
            "value": item.get("value"),
            "message": item.get("message"),
            "severity": item.get("severity"),
            "raw_data": item.get("raw_data") or {},
        }))
    return projected
