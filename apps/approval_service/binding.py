from __future__ import annotations

import hashlib
import json
from typing import Any, Mapping

_BINDING_VERSION = 1


def execution_binding_fingerprint(
    *,
    incident_id: Any,
    tool_name: Any,
    action: Any,
    target: Any,
    parameters: Mapping[str, Any] | None = None,
    timeout: Any = 30,
) -> str:
    """Return a stable SHA-256 binding for all security-relevant execution inputs."""
    payload = {
        "version": _BINDING_VERSION,
        "incident_id": str(incident_id),
        "tool_name": str(tool_name),
        "action": str(action),
        "target": str(target),
        "parameters": dict(parameters or {}),
        "timeout": int(timeout),
    }
    canonical = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=str,
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def bind_execution_metadata(metadata: Mapping[str, Any] | None, execution: Mapping[str, Any], incident_id: Any) -> dict[str, Any]:
    """Attach versioned execution binding metadata without storing parameter secrets."""
    result = dict(metadata or {})
    required = (execution.get("tool_name"), execution.get("action"), execution.get("target"), incident_id)
    if not all(value is not None and str(value).strip() for value in required):
        result["binding_complete"] = False
        return result

    result["target"] = str(execution["target"])
    result["tool_name"] = str(execution["tool_name"])
    result["binding_version"] = _BINDING_VERSION
    result["execution_binding_sha256"] = execution_binding_fingerprint(
        incident_id=incident_id,
        tool_name=execution["tool_name"],
        action=execution["action"],
        target=execution["target"],
        parameters=execution.get("parameters") or {},
        timeout=execution.get("timeout", 30),
    )
    result["binding_complete"] = True
    return result


def approval_matches_execution(approval: Mapping[str, Any], execution: Mapping[str, Any]) -> bool:
    metadata = approval.get("metadata") or {}
    if not isinstance(metadata, Mapping) or not metadata.get("binding_complete"):
        return False
    expected = metadata.get("execution_binding_sha256")
    if not expected:
        return False
    actual = execution_binding_fingerprint(
        incident_id=execution.get("incident_id"),
        tool_name=execution.get("tool_name"),
        action=execution.get("action"),
        target=execution.get("target"),
        parameters=execution.get("parameters") or {},
        timeout=execution.get("timeout", 30),
    )
    return str(expected) == actual
