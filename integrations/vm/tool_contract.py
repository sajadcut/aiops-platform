"""Small, backwards-compatible validation surface for structured VM observations.

This is deliberately independent of provider transport, and never treats
success=True as proof of host, application or recovery health.
"""
from __future__ import annotations

from typing import Any

_OBS_SCHEMA = {
    "type": "object",
    "required": ["success", "target"],
    "properties": {
        "success": {"type": "boolean"},
        "target": {"type": "string"},
        "error": {"type": ["string", "null"]},
        "observed_at": {"type": "string"},
    },
    "additionalProperties": True,
}
_FILE_ROW = {
    "type": "object",
    "required": ["mount", "blocks", "used", "available", "use_percent"],
    "properties": {
        "mount": {"type": "string"},
        "blocks": {"type": "string"},
        "used": {"type": "string"},
        "available": {"type": "string"},
        "use_percent": {"type": "string"},
    },
    "additionalProperties": True,
}
_SERVICE_ROW = {
    "type": "object",
    "required": ["name", "active_state", "sub_state"],
    "properties": {
        "name": {"type": "string"},
        "active_state": {"type": "string"},
        "sub_state": {"type": "string"},
    },
    "additionalProperties": True,
}
VALIDATED_TOOLS = frozenset({"disk_status", "list_services", "search_services"})

def output_schema(tool: str) -> dict[str, Any]:
    if tool not in VALIDATED_TOOLS:
        return {"type": "object", "additionalProperties": True}
    schema = {
        **_OBS_SCHEMA,
        "properties": {**_OBS_SCHEMA["properties"]},
    }
    if tool == "disk_status":
        schema["properties"]["filesystems"] = {"type": "array", "items": _FILE_ROW}
        schema["properties"]["inodes"] = {"type": "array", "items": _FILE_ROW}
    else:
        schema["properties"]["services"] = {"type": "array", "items": _SERVICE_ROW}
        schema["properties"]["scope_restricted"] = {"type": "boolean"}
        schema["properties"]["truncated"] = {"type": "boolean"}
    return schema


def validate_vm_observation(tool: str, target: str, payload: Any) -> dict[str, Any]:
    """Subset of the output schema validated on both modern and legacy responses.

    Avoid a soft fallback when a tool returns malformed or wrong-target data.
    An explicit unsuccessful tool result must still identify the target.
    """
    if not isinstance(payload, dict):
        raise ValueError("vm_mcp_response_not_object")
    if tool not in VALIDATED_TOOLS:
        return payload
    if type(payload.get("success")) is not bool:
        raise ValueError("vm_mcp_schema_success_invalid")
    if payload.get("target") != target:
        raise ValueError("vm_mcp_schema_target_mismatch")
    if not payload["success"]:
        return payload
    field = "filesystems" if tool == "disk_status" else "services"
    rows = payload.get(field)
    if not isinstance(rows, list):
        raise ValueError("vm_mcp_schema_inventory_missing")
    if tool == "disk_status":
        if not rows:
            raise ValueError("vm_mcp_schema_empty_disk_inventory")
        for row in rows[:256]:
            if not isinstance(row, dict) or not all(
                isinstance(row.get(key), str)
                for key in ("mount", "blocks", "used", "available", "use_percent")
            ):
                raise ValueError("vm_mcp_schema_invalid_disk_row")
    else:
        for row in rows[:500]:
            if not isinstance(row, dict) or not all(
                isinstance(row.get(key), str)
                for key in ("name", "active_state", "sub_state")
            ):
                raise ValueError("vm_mcp_schema_invalid_service_row")
    return payload
