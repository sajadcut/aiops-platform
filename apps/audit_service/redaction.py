from typing import Any, Dict

SENSITIVE_KEYS = {"password", "token", "secret", "api_key", "authorization", "private_key"}

def redact(value: Any) -> Any:
    if isinstance(value, dict):
        return {k: "***REDACTED***" if k.lower() in SENSITIVE_KEYS else redact(v) for k, v in value.items()}
    if isinstance(value, list):
        return [redact(v) for v in value]
    return value
