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
_DEPENDENCY_ROW = {
    "type": "object",
    "required": ["kind", "host", "port", "probe_status"],
    "additionalProperties": False,
    "properties": {
        "kind": {"type": "string"},
        "host": {"type": "string"},
        "port": {"type": "integer", "minimum": 1, "maximum": 65535},
        "port_inferred": {"type": "boolean"},
        "probe": {"type": "string", "enum": ["http_head", "tcp"]},
        "config_verified": {"type": "boolean"},
        "config_file": {"type": "string", "maxLength": 255},
        "config_key": {"type": "string", "maxLength": 160},
        "probe_scope": {"type": "string", "enum": [
            "origin_root_head", "transport_tcp_connect",
        ]},
        "probe_supported": {"type": "boolean"},
        "probe_status": {"type": "string"},
        "tcp_reachable": {"type": ["boolean", "null"]},
        "http_status": {"type": ["integer", "null"]},
        "tls_verified": {"type": ["boolean", "null"]},
        "tls_requested": {"type": "boolean"},
        "protocol_status": {"type": "string", "maxLength": 65},
        "protocol_supported": {"type": "boolean"},
        "protocol_health_verified": {"type": "boolean"},
        "dns_resolved": {"type": ["boolean", "null"]},
        "route_found": {"type": ["boolean", "null"]},
    },
}
VALIDATED_TOOLS = frozenset({"disk_status", "list_services", "search_services", "dependency_investigation"})

def output_schema(tool: str) -> dict[str, Any]:
    if tool not in VALIDATED_TOOLS:
        return {"type": "object", "additionalProperties": True}
    schema = {
        **_OBS_SCHEMA,
        "properties": {**_OBS_SCHEMA["properties"]},
    }
    if tool == "dependency_investigation":
        schema["properties"]["dependencies"] = {
            "type": "array", "maxItems": 6, "items": _DEPENDENCY_ROW,
        }
        schema["properties"]["config_files_read"] = {"type": "integer"}
        schema["properties"]["config_files_parse_failed"] = {"type": "integer"}
        schema["properties"]["config_files_checked"] = {"type": "integer"}
        schema["properties"]["checks_executed"] = {"type": "integer"}
        schema["properties"]["execution_authority"] = {"type": "boolean"}
    elif tool == "disk_status":
        schema["properties"]["filesystems"] = {"type": "array", "items": _FILE_ROW}
        schema["properties"]["block_devices"] = {"type": "array", "items": {"type": "object"}}
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
    if tool == "dependency_investigation":
        safe_top = {
            "success", "target", "service", "status", "diagnostic", "read_only",
            "execution_authority", "root_cause_confirmed", "application_health_verified",
            "protocol_health_verified", "config_contents_exposed", "secrets_exposed",
            "config_files_read", "config_files_parse_failed",
            "config_files_checked", "config_files_failed", "checks_executed",
            "dependencies", "limitations", "error", "observed_at",
            "investigation_status", "next_checks",
        }
        if not set(payload) <= safe_top:
            raise ValueError("vm_mcp_dependency_unexpected_payload")
        if any(payload.get(k) is not False for k in (
            "execution_authority", "root_cause_confirmed",
            "config_contents_exposed", "secrets_exposed",
        )):
            raise ValueError("vm_mcp_dependency_safety_claim_invalid")
        checks = payload.get("next_checks", [])
        permitted_hints = {
            "review_dns_configuration", "review_network_path",
            "compare_application_auth_settings",
            "inspect_client_timeouts_pool_and_errors",
            "review_tls_mode_and_certificates", "protocol_check_unavailable",
        }
        if (not isinstance(checks, list) or len(checks) > 6
                or any(hint not in permitted_hints for hint in checks)):
            raise ValueError("vm_mcp_dependency_next_checks_invalid")
        rows = payload.get("dependencies")
        if not isinstance(rows, list) or len(rows) > 6:
            raise ValueError("vm_mcp_dependency_inventory_invalid")
        safe_fields = set(_DEPENDENCY_ROW["properties"])
        from integrations.vm.dependency_discovery import safe_config_key
        from integrations.vm.general_config_review import checked_config_path
        for row in rows:
            if not isinstance(row, dict) or not set(row) <= safe_fields:
                raise ValueError("vm_mcp_dependency_field_invalid")
            source_file = row.get("config_file")
            if source_file is not None:
                try:
                    if checked_config_path(source_file) != source_file:
                        raise ValueError("noncanonical_dependency_config_path")
                except (TypeError, ValueError):
                    raise ValueError("vm_mcp_dependency_config_path_invalid") from None
            source_key = row.get("config_key")
            if source_key is not None and (
                not isinstance(source_key, str)
                or safe_config_key(tuple(source_key.split("."))) != source_key
            ):
                raise ValueError("vm_mcp_dependency_config_key_invalid")
            if row.get("protocol_status") is not None and row["kind"] != "redis":
                raise ValueError("vm_mcp_dependency_protocol_mismatch")
            if row.get("tls_requested") is not None and row["kind"] != "redis":
                raise ValueError("vm_mcp_dependency_tls_mismatch")
            scope = row.get("probe_scope")
            if scope is not None and (
                (scope == "origin_root_head" and row.get("probe") != "http_head")
                or (scope == "transport_tcp_connect" and row.get("probe") != "tcp")
                or scope not in {"origin_root_head", "transport_tcp_connect"}
            ):
                raise ValueError("vm_mcp_dependency_probe_scope_invalid")
            if (not isinstance(row.get("kind"), str)
                    or not isinstance(row.get("host"), str)
                    or type(row.get("port")) is not int
                    or not 1 <= row["port"] <= 65535
                    or row.get("config_verified") is not True
                    or not isinstance(row.get("probe_status"), str)):
                raise ValueError("vm_mcp_dependency_row_invalid")
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
