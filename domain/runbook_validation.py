from typing import Any, Dict

REQUIRED = ("owner", "version", "preconditions", "steps", "timeout", "rollback")

def validate_runbook(data: Dict[str, Any]) -> Dict[str, Any]:
    missing = [key for key in REQUIRED if key not in data]
    valid = not missing and isinstance(data.get("steps"), list) and isinstance(data.get("rollback"), list)
    return {"valid": valid, "missing": missing}
