"""Protocol version compatibility, output contracts and fail-closed response parsing."""
import json
import pytest

from apps.mcp_server.main import _TOOL_SCHEMAS, _vm_mcp_tool_metadata, _vm_mcp_wire_result
from integrations.vm.tool_contract import output_schema, validate_vm_observation


def test_every_vm_tool_advertises_output_schema_and_governed_annotations():
    for name, schema in _TOOL_SCHEMAS["vm"].items():
        meta = _vm_mcp_tool_metadata(name, schema)
        assert meta["outputSchema"]["type"] == "object"
        assert meta["annotations"]["readOnlyHint"] == (name not in {
            "start_service", "restart_service", "reload_service", "config_change_apply"})
        assert meta["annotations"]["destructiveHint"] is (name == "config_change_apply")
    assert output_schema("disk_status")["properties"]["filesystems"]["type"] == "array"


def test_legacy_wire_format_remains_unchanged():
    payload = {"success": True, "target": "vm-1", "filesystems": []}
    result = _vm_mcp_wire_result(payload, protocol_version="2025-03-26")
    assert result == {"content": [payload]}


def test_modern_opt_in_returns_structured_and_text_content():
    payload = {"success": True, "target": "vm-1", "filesystems": []}
    wire = _vm_mcp_wire_result(payload, protocol_version="2025-06-18")
    assert wire["structuredContent"] == payload
    assert wire["content"][0]["type"] == "text"
    assert json.loads(wire["content"][0]["text"]) == payload
    assert _vm_mcp_wire_result(payload, protocol_version="2025-11-25") == wire


def test_wrong_target_and_invalid_rows_fail_closed():
    payload = {"success": True, "target": "vm-1", "filesystems": [
        {"mount": "/", "blocks": "100", "used": "10", "available": "90", "use_percent": "10%"}]}
    assert validate_vm_observation("disk_status", "vm-1", payload) == payload
    with pytest.raises(ValueError, match="target_mismatch"):
        validate_vm_observation("disk_status", "vm-2", payload)
    with pytest.raises(ValueError, match="inventory_missing"):
        validate_vm_observation("disk_status", "vm-1", {"success": True, "target": "vm-1"})
    with pytest.raises(ValueError, match="success_invalid"):
        validate_vm_observation("disk_status", "vm-1", {"success": "true", "target": "vm-1"})


def test_failed_observation_not_silent_success():
    observation = {"success": False, "target": "vm-1", "error": "ssh_command_failed"}
    assert validate_vm_observation("disk_status", "vm-1", observation)["success"] is False
