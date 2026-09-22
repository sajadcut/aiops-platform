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
