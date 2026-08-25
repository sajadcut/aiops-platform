from __future__ import annotations

from typing import Any, Dict, List


BASE_REQUIRED = ("owner", "version", "preconditions", "steps", "timeout", "rollback")
STRICT_REQUIRED = BASE_REQUIRED + ("risk", "verification")
ALLOWED_RISKS = {"low", "medium", "high", "critical"}
ALLOWED_DIRECTIONS = {"lower_is_better", "higher_is_better", "equals", "absent"}


def validate_runbook(data: Dict[str, Any], *, strict: bool = False) -> Dict[str, Any]:
    """Validate a runbook definition.

    ``strict=False`` preserves the historical lightweight validation contract
    used by older callers/tests. Production registry/execution paths MUST call
    ``strict=True``; that mode requires identity, risk, verification objectives,
    non-empty actionable steps and stronger type constraints.
    """
    required = STRICT_REQUIRED if strict else BASE_REQUIRED
    missing: List[str] = [key for key in required if key not in data]
    errors: List[str] = []

    runbook_id = str(data.get("id") or data.get("name") or "").strip()
    if strict and not runbook_id:
        errors.append("id_or_name_required")
    if not str(data.get("owner") or "").strip():
        errors.append("owner_required")
    if not str(data.get("version") or "").strip():
        errors.append("version_required")

    preconditions = data.get("preconditions")
    if preconditions is not None and not isinstance(preconditions, list):
        errors.append("preconditions_must_be_list")

    steps = data.get("steps")
    if not isinstance(steps, list):
        errors.append("steps_must_be_list")
    elif strict and not steps:
        errors.append("steps_must_be_non_empty_list")
    elif strict and any(not isinstance(step, dict) or not str(step.get("action") or "").strip() for step in steps):
        errors.append("each_step_requires_action")

    rollback = data.get("rollback")
    if not isinstance(rollback, list):
        errors.append("rollback_must_be_list")

    timeout = data.get("timeout")
    if strict and (isinstance(timeout, bool) or not isinstance(timeout, int) or timeout <= 0):
        errors.append("timeout_must_be_positive_integer")

    risk = str(data.get("risk") or "").strip().lower()
    if strict and risk not in ALLOWED_RISKS:
        errors.append("risk_not_allowlisted")

    verification = data.get("verification")
    if strict:
        if not isinstance(verification, dict):
            errors.append("verification_must_be_object")
        else:
            checks = verification.get("checks")
            if not isinstance(checks, list) or not checks:
                errors.append("verification_checks_required")
            else:
                for index, check in enumerate(checks):
                    if not isinstance(check, dict):
                        errors.append(f"verification_check_{index}_must_be_object")
                        continue
                    if not str(check.get("metric") or check.get("signal") or check.get("state") or "").strip():
                        errors.append(f"verification_check_{index}_target_required")
                    direction = str(check.get("direction") or "").strip()
                    if direction not in ALLOWED_DIRECTIONS:
                        errors.append(f"verification_check_{index}_direction_invalid")

    return {
        "valid": not missing and not errors,
        "missing": missing,
        "errors": errors,
        "runbook_id": runbook_id or None,
        "strict": strict,
    }
