from __future__ import annotations

from typing import Any, Dict


REQUIRED = ("name", "owner", "version", "preconditions", "steps", "timeout", "rollback")


def validate_runbook(data: Dict[str, Any]) -> Dict[str, Any]:
    missing = [key for key in REQUIRED if key not in data]
    errors: list[str] = []
    if not isinstance(data.get("name"), str) or not str(data.get("name", "")).strip():
        errors.append("name must be a non-empty string")
    for key in ("preconditions", "steps", "rollback"):
        if key in data and not isinstance(data[key], list):
            errors.append(f"{key} must be a list")
    if "timeout" in data:
        timeout = data["timeout"]
        if not isinstance(timeout, int) or timeout <= 0 or timeout > 3600:
            errors.append("timeout must be an integer between 1 and 3600 seconds")
    if "risk_level" in data and str(data["risk_level"]).lower() not in {"low", "medium", "high", "critical"}:
        errors.append("risk_level must be low, medium, high, or critical")

    valid = not missing and not errors and bool(data.get("steps"))
    return {"valid": valid, "missing": missing, "errors": errors}