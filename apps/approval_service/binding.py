from __future__ import annotations

import hashlib
import json
from typing import Any, Dict

from domain.contracts.config import settings

BINDING_VERSION = 1


def _canonical_parameters(parameters: Any) -> Dict[str, Any]:
    return dict(parameters or {}) if isinstance(parameters or {}, dict) else {}


def execution_intent(
    *,
    incident_id: Any,
    tool_name: Any,
    action: Any,
    target: Any,
    parameters: Any = None,
    timeout: Any = 30,
    runbook_id: Any = None,
    runbook_version: Any = None,
    rollback: Any = False,
) -> Dict[str, Any]:
    return {
        "binding_version": BINDING_VERSION,
        "environment": settings.APP_ENV,
        "incident_id": str(incident_id or ""),
        "tool_name": str(tool_name or ""),
        "action": str(action or ""),
        "target": str(target or ""),
        "parameters": _canonical_parameters(parameters),
        "timeout": int(timeout or 30),
        "runbook_id": str(runbook_id) if runbook_id not in (None, "") else None,
        "runbook_version": str(runbook_version) if runbook_version not in (None, "") else None,
        "rollback": bool(rollback),
    }


def intent_digest(intent: Dict[str, Any]) -> str:
    encoded = json.dumps(intent, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def bind_metadata(metadata: Dict[str, Any] | None, **intent_fields: Any) -> Dict[str, Any]:
    """Store a non-secret readable summary plus a digest of the complete intent.

    Parameters are included in the digest but are deliberately not copied into
    approval metadata, preventing credentials or sensitive operational values
    from being persisted merely for approval binding.
    """
    intent = execution_intent(**intent_fields)
    if not all((intent["incident_id"], intent["tool_name"], intent["action"], intent["target"])):
        raise ValueError("approval_binding_incomplete")
    result = dict(metadata or {})
    result.update(
        {
            "binding_complete": True,
            "binding_version": BINDING_VERSION,
            "binding_digest": intent_digest(intent),
            "environment": intent["environment"],
            "tool_name": intent["tool_name"],
            "target": intent["target"],
            "timeout": intent["timeout"],
            "runbook_id": intent["runbook_id"],
            "runbook_version": intent["runbook_version"],
            "rollback": intent["rollback"],
        }
    )
    return result


def assert_bound(approval: Dict[str, Any], **intent_fields: Any) -> None:
    if str(approval.get("status") or "").lower() != "approved":
        raise ValueError("approval_not_approved")
    intent = execution_intent(**intent_fields)
    metadata = dict(approval.get("metadata") or {})
    if not metadata.get("binding_complete") or int(metadata.get("binding_version") or 0) != BINDING_VERSION:
        raise ValueError("approval_binding_incomplete")
    if str(approval.get("incident_id")) != intent["incident_id"]:
        raise ValueError("approval_incident_mismatch")
    if str(approval.get("action")) != intent["action"]:
        raise ValueError("approval_action_mismatch")
    if str(metadata.get("tool_name")) != intent["tool_name"]:
        raise ValueError("approval_tool_mismatch")
    if str(metadata.get("target")) != intent["target"]:
        raise ValueError("approval_target_mismatch")
    if str(metadata.get("environment")) != intent["environment"]:
        raise ValueError("approval_environment_mismatch")
    if str(metadata.get("binding_digest") or "") != intent_digest(intent):
        raise ValueError("approval_execution_intent_mismatch")
