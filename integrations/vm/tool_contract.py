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
        "config_port_key": {"type": "string", "maxLength": 160},
        "endpoint_source": {"type": "string", "maxLength": 70},
        "probe_scope": {"type": "string", "enum": [
            "origin_root_head", "transport_tcp_connect",
            "not_executed_inferred_port",
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
            "llm_field_binding_status", "llm_field_binding_files",
            "binding_candidates",
        }
        if not set(payload) <= safe_top:
            raise ValueError("vm_mcp_dependency_unexpected_payload")
        llm_status = payload.get("llm_field_binding_status")
        allowed_llm = {
            "not_requested", "no_safe_host_port_candidates",
            "trusted_llm_not_configured", "verified",
            "llm_response_invalid", "llm_response_incomplete",
            "llm_unsubstantiated_selection", "llm_cross_dependency_selection",
            "llm_binding_unavailable", "no_model_match",
            "central_llm_required", "central_llm_unavailable", "config_changed",
        }
        if llm_status is not None and llm_status not in allowed_llm:
            raise ValueError("vm_mcp_dependency_llm_status_invalid")
        candidates = payload.get("binding_candidates", [])
        if not isinstance(candidates, list) or len(candidates) > 4:
            raise ValueError("vm_mcp_dependency_candidates_invalid")
        if candidates:
            import re
            from integrations.vm.dependency_discovery import (
                KINDS, safe_config_key, safe_host, safe_port,
            )
            from integrations.vm.general_config_review import checked_config_path
            allowed_kinds = {kind for kind, _ in KINDS.values()}
            used_indices: set[int] = set()
            for entry in candidates:
                required_candidate_fields = {
                    "file_index", "config_file", "sha256",
                    "host_fields", "port_fields", "inline_endpoint_fields",
                }
                if (not isinstance(entry, dict)
                        or not required_candidate_fields <= set(entry)
                        or not set(entry) <= required_candidate_fields | {"complete_config_b64"}):
                    raise ValueError("vm_mcp_dependency_candidate_shape_invalid")
                idx, digest, path = (entry["file_index"], entry["sha256"],
                                     entry["config_file"])
                if (type(idx) is not int or idx not in range(4)
                        or idx in used_indices or not isinstance(digest, str)
                        or re.fullmatch(r"[a-f0-9]{64}", digest) is None
                        or not isinstance(path, str)
                        or checked_config_path(path) != path):
                    raise ValueError("vm_mcp_dependency_candidate_identity_invalid")
                used_indices.add(idx)
                if "complete_config_b64" in entry:
                    # Never trust even an authenticated worker's claim that its
                    # unredacted context is the same systemd-derived file.
                    import base64
                    import binascii
                    import hashlib
                    encoded = entry["complete_config_b64"]
                    if not isinstance(encoded, str) or len(encoded) > 87384:
                        raise ValueError("vm_mcp_dependency_complete_config_too_large")
                    try:
                        full_bytes = base64.b64decode(encoded, validate=True)
                    except (ValueError, binascii.Error) as exc:
                        raise ValueError("vm_mcp_dependency_complete_config_invalid") from exc
                    if (not 1 <= len(full_bytes) <= 65536
                            or hashlib.sha256(full_bytes).hexdigest() != digest):
                        raise ValueError("vm_mcp_dependency_complete_config_digest_invalid")
                for field, limit, prefix in (
                    ("host_fields", 16, "h"), ("port_fields", 16, "p"),
                    ("inline_endpoint_fields", 8, "e"),
                ):
                    items = entry[field]
                    if not isinstance(items, list) or len(items) > limit:
                        raise ValueError("vm_mcp_dependency_candidate_inventory_invalid")
                    ids: set[str] = set()
                    for j, row in enumerate(items):
                        if not isinstance(row, dict) or row.get("id") != f"{prefix}{j}":
                            raise ValueError("vm_mcp_dependency_candidate_id_invalid")
                        if row["id"] in ids:
                            raise ValueError("vm_mcp_dependency_candidate_duplicate_id")
                        ids.add(row["id"])
                        required = (
                            {"id", "path", "host", "family"} if prefix == "h" else
                            {"id", "path", "port", "family"} if prefix == "p" else
                            {"id", "path", "kind", "host", "port"}
                        )
                        if set(row) != required:
                            raise ValueError("vm_mcp_dependency_candidate_field_invalid")
                        parts = str(row["path"]).split(".")
                        if safe_config_key(parts) != row["path"]:
                            raise ValueError("vm_mcp_dependency_candidate_path_invalid")
                        family = row.get("family", row.get("kind"))
                        if family not in allowed_kinds:
                            raise ValueError("vm_mcp_dependency_candidate_kind_invalid")
                        if "host" in row and safe_host(row["host"]) != row["host"]:
                            raise ValueError("vm_mcp_dependency_candidate_host_invalid")
                        if "port" in row and safe_port(row["port"]) != row["port"]:
                            raise ValueError("vm_mcp_dependency_candidate_port_invalid")
        metadata = payload.get("llm_field_binding_files", [])
        if not isinstance(metadata, list) or len(metadata) > 4:
            raise ValueError("vm_mcp_dependency_llm_metadata_invalid")
        from integrations.vm.general_config_review import checked_config_path
        for entry in metadata:
            if not isinstance(entry, dict) or not set(entry) <= {
                "config_file", "status", "candidate_host_count",
                "candidate_port_count", "candidate_inline_endpoint_count",
                "verified_pair_count",
            } or not {"config_file", "status", "candidate_host_count",
                      "candidate_port_count", "verified_pair_count"} <= set(entry):
                raise ValueError("vm_mcp_dependency_llm_metadata_invalid")
            try:
                if checked_config_path(entry["config_file"]) != entry["config_file"]:
                    raise ValueError("noncanonical")
            except (KeyError, TypeError, ValueError):
                raise ValueError("vm_mcp_dependency_llm_file_invalid") from None
            if entry["status"] not in allowed_llm or any(
                type(entry.get(k)) is not int or not 0 <= entry[k] <= 16
                for k in ("candidate_host_count", "candidate_port_count",
                          "verified_pair_count")
            ) or (
                entry.get("candidate_inline_endpoint_count") is not None
                and (type(entry["candidate_inline_endpoint_count"]) is not int
                     or not 0 <= entry["candidate_inline_endpoint_count"] <= 8)
            ):
                raise ValueError("vm_mcp_dependency_llm_metadata_invalid")
        if payload.get("execution_authority") is not False or payload.get("root_cause_confirmed") is not False:
            raise ValueError("vm_mcp_dependency_safety_claim_invalid")
        # Only a bounded discover response may admit explicit temporary
        # credential-bearing content. Subsequent probe results must revert
        # to non-exposure claims; no model output can authorize execution.
        has_raw = any(
            isinstance(row, dict) and "complete_config_b64" in row
            for row in candidates
        )
        expected_exposure = bool(has_raw)
        if (payload.get("config_contents_exposed") is not expected_exposure
                or payload.get("secrets_exposed") is not expected_exposure
                or (has_raw and payload.get("status") != "binding_candidates_ready")):
            raise ValueError("vm_mcp_dependency_safety_claim_invalid")
        checks = payload.get("next_checks", [])
        permitted_hints = {
            "review_dns_configuration", "review_network_path",
            "compare_application_auth_settings",
            "inspect_client_timeouts_pool_and_errors",
            "review_tls_mode_and_certificates", "protocol_check_unavailable",
            "verify_effective_dependency_port",
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
            port_key = row.get("config_port_key")
            if port_key is not None and (
                not isinstance(port_key, str)
                or safe_config_key(tuple(port_key.split("."))) != port_key
            ):
                raise ValueError("vm_mcp_dependency_port_key_invalid")
            source = row.get("endpoint_source")
            if source is not None and source not in {
                "llm_binding_independently_verified",
            }:
                raise ValueError("vm_mcp_dependency_endpoint_source_invalid")
            if row.get("protocol_status") is not None and row["kind"] != "redis":
                raise ValueError("vm_mcp_dependency_protocol_mismatch")
            if row.get("tls_requested") is not None and row["kind"] != "redis":
                raise ValueError("vm_mcp_dependency_tls_mismatch")
            scope = row.get("probe_scope")
            if scope is not None and (
                (scope == "origin_root_head" and row.get("probe") != "http_head")
                or (scope == "transport_tcp_connect" and row.get("probe") != "tcp")
                or scope not in {"origin_root_head", "transport_tcp_connect",
                                 "not_executed_inferred_port"}
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
