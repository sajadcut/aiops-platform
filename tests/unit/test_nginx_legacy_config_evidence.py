"""Regression tests for legacy VM MCP configuration-validator payloads.

An HTTP/MCP 200 response can contain a failed syntax validation; only the
semantic valid flag determines whether configuration is safe to start.
"""

from agents.vm.deterministic import classify_vm_service_fault
from apps.operator_summary import _observed
from integrations.vm.service_adapters import (
    enrich_legacy_config_diagnostic,
    parse_config_diagnostic,
)


ERROR_OUTPUT = (
    '2026/10/13 16:09:05 [warn] 3835689#3835689: the "user" directive '
    'makes sense only if the master process runs with super-user privileges, '
    'ignored in /etc/nginx/nginx.conf:43\n'
    '2026/10/13 16:09:05 [emerg] 3835689#3835689: unexpected "{" '
    'in /etc/nginx/nginx.conf:103\n'
    'nginx: configuration file /etc/nginx/nginx.conf test failed'
)
TARGET = "10.248.16.82"


def _row(diag, reference, **fields):
    return {
        "source": "vm_mcp",
        "type": "telemetry",
        "reference": reference,
        "raw_data": {"diagnostic": diag, "target": TARGET, "service": "nginx", **fields},
    }


def test_nginx_fatal_syntax_line_wins_over_earlier_warning():
    parsed = parse_config_diagnostic(ERROR_OUTPUT)
    assert parsed["config_file"] == "/etc/nginx/nginx.conf"
    assert parsed["error_line"] == 103
    assert 'unexpected "{"' in parsed["syntax_error"]
    assert "warn" not in parsed["syntax_error"].lower()


def test_legacy_payload_is_enriched_without_claiming_validity_or_write_authority():
    raw = {
        "success": True, "supported": True, "valid": False,
        "service": "nginx", "target": TARGET, "exit_code": 1,
        "detail": ERROR_OUTPUT,
    }
    enriched = enrich_legacy_config_diagnostic(raw)
    assert enriched["valid"] is False
    assert enriched["error_line"] == 103
    assert enriched["config_file"] == "/etc/nginx/nginx.conf"
    assert enriched["config_path_source"] == "validator_output"
    assert "error_line" not in raw

    # Transport/permission failures do not become syntactically proven faults.
    for bad in (
        {**raw, "success": False, "valid": None},
        {**raw, "supported": False},
        {**raw, "valid": True},
    ):
        assert "error_line" not in enrich_legacy_config_diagnostic(bad)


def test_operator_summary_recovers_exact_fault_from_legacy_mcp_result():
    rows = [
        _row("service_status", "vm-status-1", active_state="inactive", sub_state="dead"),
        _row("config_validate", "vm-config-1", success=True, supported=True,
             valid=False, exit_code=1, detail=ERROR_OUTPUT),
    ]
    observed = _observed({"service": "nginx"}, {}, rows)
    config = observed["config_validate"]
    assert config["valid"] is False
    assert config["error_line"] == 103
    assert config["config_file"] == "/etc/nginx/nginx.conf"
    assert 'unexpected "{"' in config["syntax_error"]
    assert config["evidence_id"] == "vm-config-1"


def test_deterministic_vm_fault_keeps_config_invalid_and_does_not_propose_start():
    evidence = [
        _row("service_status", "status-1", active_state="inactive", sub_state="dead"),
        _row("config_validate", "config-1", success=True, supported=True,
             valid=False, exit_code=1, detail=ERROR_OUTPUT),
        _row("process_status", "process-1", running=False),
    ]
    fault = classify_vm_service_fault(evidence, "nginx")
    assert fault is not None
    assert fault["fault_code"] == "service_configuration_invalid"
    assert fault["config_file"] == "/etc/nginx/nginx.conf"
    assert fault["error_line"] == 103
    assert fault["suggested_action"] is None
    assert fault["requires_operator_review"] is True
    assert "start_service" in fault["remediation_candidate"]
