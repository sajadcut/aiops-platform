import pytest

from apps.execution_service import ExecutionResult
from apps.runbook_service.registry import RunbookRegistry
from apps.runbook_service.runtime_guard import RunbookRuntimeGuard


def _execution_result(action: str, result: dict, *, success: bool = True):
    return ExecutionResult(
        success=success,
        tool_name="vm_telemetry",
        action=action,
        target="10.100.6.199",
        result=result,
        error=None if success else "read_failed",
    )


@pytest.mark.asyncio
async def test_runtime_guard_collects_canonical_vm_evidence(monkeypatch):
    async def fake_vm_read(*, action, target, parameters, incident_id):
        assert target == "10.100.6.199"
        assert incident_id == "incident-1"
        payloads = {
            "service_status": {
                "active_state": "inactive",
                "sub_state": "dead",
            },
            "config_validate": {
                "supported": True,
                "valid": True,
            },
            "port_listener_status": {
                "listening": False,
            },
            "tcp_check": {
                "reachable": False,
            },
        }
        return _execution_result(action, payloads[action])

    monkeypatch.setattr(
        RunbookRuntimeGuard,
        "_vm_read",
        staticmethod(fake_vm_read),
    )

    snapshot = await RunbookRuntimeGuard.collect_snapshot(
        runbook_id="vm-service-recovery",
        target="10.100.6.199",
        parameters={"service": "nginx", "target_port": 86},
        incident_id="incident-1",
        phase="pre",
    )

    assert snapshot["supported"] is True
    assert snapshot["read_success"] is True
    assert len(snapshot["evidence"]) == 4
    diagnostics = {
        item["raw_data"]["diagnostic"] for item in snapshot["evidence"]
    }
    assert diagnostics == {
        "service_status",
        "config_validate",
        "port_listener_status",
        "tcp_check",
    }
    assert all(
        item["raw_data"]["target"] == "10.100.6.199"
        for item in snapshot["evidence"]
    )
    assert all(
        item["raw_data"]["service"] == "nginx"
        for item in snapshot["evidence"]
    )


def test_runtime_guard_preflight_blocks_recovered_service():
    evidence = [
        {
            "source": "vm_mcp",
            "reference": "svc",
            "raw_data": {
                "diagnostic": "service_status",
                "target": "10.100.6.199",
                "service": "nginx",
                "active_state": "active",
            },
        },
        {
            "source": "vm_mcp",
            "reference": "cfg",
            "raw_data": {
                "diagnostic": "config_validate",
                "target": "10.100.6.199",
                "service": "nginx",
                "supported": True,
                "valid": True,
            },
        },
    ]

    result = RunbookRuntimeGuard.preflight(
        runbook_id="vm-service-recovery",
        tool_name="ssh_vm",
        action="start_service",
        target="10.100.6.199",
        parameters={"service": "nginx"},
        incident_id="incident-1",
        evidence=evidence,
    )

    assert result["safe_to_execute"] is False
    assert result["reason"] == "service_no_longer_unhealthy"


def test_runtime_guard_preflight_allows_live_stopped_service_with_valid_config():
    evidence = [
        {
            "source": "vm_mcp",
            "reference": "svc",
            "raw_data": {
                "diagnostic": "service_status",
                "target": "10.100.6.199",
                "service": "nginx",
                "active_state": "inactive",
            },
        },
        {
            "source": "vm_mcp",
            "reference": "cfg",
            "raw_data": {
                "diagnostic": "config_validate",
                "target": "10.100.6.199",
                "service": "nginx",
                "supported": True,
                "valid": True,
            },
        },
    ]

    result = RunbookRuntimeGuard.preflight(
        runbook_id="vm-service-recovery",
        tool_name="ssh_vm",
        action="start_service",
        target="10.100.6.199",
        parameters={"service": "nginx"},
        incident_id="incident-1",
        evidence=evidence,
    )

    assert result["safe_to_execute"] is True
    assert result["reason"] == "fresh_execution_preconditions_satisfied"


@pytest.mark.asyncio
async def test_runtime_guard_verify_uses_registered_runbook_objectives():
    runbook = RunbookRegistry("runbooks").get("vm-service-recovery")
    before = {
        "live_evidence": {
            "evidence": [
                {
                    "reference": "svc-before",
                    "raw_data": {
                        "diagnostic": "service_status",
                        "active_state": "inactive",
                    },
                },
                {
                    "reference": "port-before",
                    "raw_data": {
                        "diagnostic": "port_listener_status",
                        "listening": False,
                    },
                },
            ]
        }
    }
    after = {
        "live_evidence": {
            "evidence": [
                {
                    "reference": "svc-after",
                    "raw_data": {
                        "diagnostic": "service_status",
                        "active_state": "active",
                    },
                },
                {
                    "reference": "port-after",
                    "raw_data": {
                        "diagnostic": "port_listener_status",
                        "listening": True,
                    },
                },
            ]
        }
    }

    result = await RunbookRuntimeGuard.verify(
        runbook=runbook,
        action="start_service",
        service="nginx",
        before_context=before,
        after_context=after,
    )

    assert result.status.value == "success"
    assert result.required_objectives_met is True
    assert {item["target"] for item in result.objective_results} == {
        "service_active",
        "port_listening",
    }


@pytest.mark.asyncio
async def test_unsupported_generic_config_collects_dotnet_specific_live_checks(monkeypatch):
    calls = []
    async def fake_vm_read(*, action, target, parameters, incident_id):
        calls.append(action)
        rows = {
            "service_status": {"success": True, "active_state": "failed"},
            "config_validate": {
                "success": True, "supported": False, "valid": None,
                "detail": "config_validation_adapter_unavailable",
            },
            "service_runtime_discovery": {
                "success": True, "runtime": "dotnet",
                "entrypoint": "/data/service/Api.dll",
                "publish_directory": "/data/service",
            },
            "dotnet_config_syntax": {
                "success": True, "supported": True, "runtime": "dotnet",
                "validator": "aiops-local-python-json-syntax-only",
                "validated_scope": "json_syntax_only",
                "syntax_valid": True, "status": "syntax_valid",
                "config_contents_exposed": False,
                "config_values_persisted": False,
                "environment_values_read": False,
                "files": [{"file": "appsettings.json", "status": "valid_json_syntax"}],
            },
        }
        return _execution_result(action, rows[action])
    monkeypatch.setattr(RunbookRuntimeGuard, "_vm_read", staticmethod(fake_vm_read))
    snap = await RunbookRuntimeGuard.collect_snapshot(
        runbook_id="vm-service-recovery", target="10.100.6.199",
        parameters={"service": "gfpapi"}, incident_id="incident-1",
        phase="chat_preapproval",
    )
    assert calls == ["service_status", "config_validate",
                     "service_runtime_discovery", "dotnet_config_syntax"]
    gate = RunbookRuntimeGuard.preflight(
        runbook_id="vm-service-recovery", tool_name="ssh_vm",
        action="restart_service", target="10.100.6.199",
        parameters={"service": "gfpapi"}, incident_id="incident-1",
        evidence=snap["evidence"],
    )
    assert gate["safe_to_execute"] is True
    assert gate["validation_scope"] == "dotnet_json_syntax_only"
    assert gate["configuration_semantics_valid"] is None
    assert len(gate["evidence_refs"]) == 4
    for action in ("reload_service", "start_service"):
        status = gate if action == "restart_service" else RunbookRuntimeGuard.preflight(
            runbook_id="vm-service-recovery", tool_name="ssh_vm",
            action=action, target="10.100.6.199",
            parameters={"service": "gfpapi"}, incident_id="incident-1",
            evidence=snap["evidence"],
        )
        if action != "restart_service":
            assert status["safe_to_execute"] is False


@pytest.mark.asyncio
async def test_unsupported_generic_config_without_dotnet_does_not_auto_pass(monkeypatch):
    calls = []
    async def fake_vm_read(*, action, target, parameters, incident_id):
        calls.append(action)
        rows = {
            "service_status": {"success": True, "active_state": "failed"},
            "config_validate": {
                "success": True, "supported": False, "valid": None,
                "detail": "config_validation_adapter_unavailable",
            },
            "service_runtime_discovery": {"success": True, "runtime": "unknown"},
        }
        return _execution_result(action, rows[action])
    monkeypatch.setattr(RunbookRuntimeGuard, "_vm_read", staticmethod(fake_vm_read))
    snap = await RunbookRuntimeGuard.collect_snapshot(
        runbook_id="vm-service-recovery", target="10.100.6.199",
        parameters={"service": "unknown-api"}, incident_id="incident-1",
        phase="chat_preapproval",
    )
    assert calls == ["service_status", "config_validate", "service_runtime_discovery"]
    gate = RunbookRuntimeGuard.preflight(
        runbook_id="vm-service-recovery", tool_name="ssh_vm", action="restart_service",
        target="10.100.6.199", parameters={"service": "unknown-api"},
        incident_id="incident-1", evidence=snap["evidence"],
    )
    assert gate["safe_to_execute"] is False
    assert gate["reason"] == "dotnet_runtime_identity_unverified"


def test_runtime_preflight_ignores_incidental_full_var_log_warning_after_valid_nginx_syntax():
    """A disk alarm never substitutes for failed config or systemd evidence."""
    bound = {"target": "10.100.6.199", "service": "nginx"}
    evidence = [
        {"source": "vm_mcp", "reference": "live-svc", "raw_data": {
            **bound, "diagnostic": "service_status",
            "success": True, "active_state": "inactive", "sub_state": "dead",
        }},
        {"source": "vm_mcp", "reference": "live-config", "raw_data": {
            **bound, "diagnostic": "config_validate", "supported": True,
            "success": True, "valid": True, "exit_code": 0,
            "nonfatal_warnings": ["sudo_audit_log_write_failed_enospc"],
        }},
        {"source": "vm_mcp", "reference": "storage", "raw_data": {
            "target": "10.100.6.199", "diagnostic": "disk_status",
            "filesystems": [{"mount": "/var/log", "use_percent": "100%"}],
        }},
    ]
    result = RunbookRuntimeGuard.preflight(
        runbook_id="vm-service-recovery", tool_name="ssh_vm",
        action="start_service", target="10.100.6.199",
        parameters={"service": "nginx"}, incident_id="incident-1",
        evidence=evidence,
    )
    assert result["safe_to_execute"] is True
    assert result["action"] == "start_service"

    # Actual configuration failure still blocks; no unsafe bypass.
    evidence[1]["raw_data"]["valid"] = False
    result = RunbookRuntimeGuard.preflight(
        runbook_id="vm-service-recovery", tool_name="ssh_vm",
        action="start_service", target="10.100.6.199",
        parameters={"service": "nginx"}, incident_id="incident-1",
        evidence=evidence,
    )
    assert result["safe_to_execute"] is False
    assert result["reason"] == "service_configuration_invalid"
