from apps.memory_service.builder import OperationalMemoryBuilder
from apps.runbook_service.learning import build_runbook_memory_state


def _snapshot(active: bool, listening: bool):
    return {
        "evidence": [
            {
                "source": "vm_mcp",
                "type": "event",
                "reference": f"svc-{active}",
                "raw_data": {
                    "diagnostic": "service_status",
                    "target": "10.100.6.199",
                    "service": "nginx",
                    "active_state": "active" if active else "inactive",
                },
            },
            {
                "source": "vm_mcp",
                "type": "event",
                "reference": f"port-{listening}",
                "raw_data": {
                    "diagnostic": "port_listener_status",
                    "target": "10.100.6.199",
                    "service": "nginx",
                    "port": 86,
                    "listening": listening,
                },
            },
        ]
    }


def _runbook():
    return {
        "id": "vm-service-recovery",
        "version": "1.1",
        "risk": "high",
    }


def test_direct_runbook_success_builds_verified_operational_memory_episode():
    state = build_runbook_memory_state(
        incident_id="11111111-1111-1111-1111-111111111111",
        runbook=_runbook(),
        tool_name="ssh_vm",
        action="start_service",
        target="10.100.6.199",
        parameters={"service": "nginx", "target_port": 86},
        approval={
            "approval_id": "approval-1",
            "status": "consumed",
        },
        execution_result={
            "success": True,
            "tool_name": "ssh_vm",
            "action": "start_service",
            "target": "10.100.6.199",
        },
        verification_result={
            "status": "success",
            "confidence": 0.95,
            "before_state": {
                "service_active": 0.0,
                "port_listening": 0.0,
            },
            "after_state": {
                "service_active": 1.0,
                "port_listening": 1.0,
            },
            "metric_directions": {
                "service_active": "higher_is_better",
                "port_listening": "higher_is_better",
            },
            "evidence_refs": ["svc-True", "port-True"],
            "message": "registered objectives met",
        },
        before_snapshot=_snapshot(False, False),
        after_snapshot=_snapshot(True, True),
    )

    episode = OperationalMemoryBuilder.build(state)

    assert episode["memory_outcome_class"] == "successful_recovery"
    assert episode["verification_result"] == "success"
    assert episode["actual_remediation"]["runbook_id"] == "vm-service-recovery"
    assert episode["actual_remediation"]["action"] == "start_service"
    assert episode["evidence_provenance"]["evidence_count"] == 4


def test_direct_runbook_execution_failure_builds_negative_memory_episode():
    state = build_runbook_memory_state(
        incident_id="22222222-2222-2222-2222-222222222222",
        runbook=_runbook(),
        tool_name="ssh_vm",
        action="start_service",
        target="10.100.6.199",
        parameters={"service": "nginx", "target_port": 86},
        approval={
            "approval_id": "approval-2",
            "status": "consumed",
        },
        execution_result={
            "success": False,
            "tool_name": "ssh_vm",
            "action": "start_service",
            "target": "10.100.6.199",
            "error": "mcp_write_failed",
        },
        verification_result={
            "status": "failed",
            "confidence": 0.0,
            "before_state": {},
            "after_state": {},
            "evidence_refs": [],
            "message": "mcp_write_failed",
        },
        before_snapshot=_snapshot(False, False),
        after_snapshot=None,
    )

    episode = OperationalMemoryBuilder.build(state)

    assert episode["memory_outcome_class"] == "failed_recovery"
    assert episode["verification_result"] == "failed"
    assert episode["actual_remediation"]["execution_success"] is False
    assert episode["actual_remediation"]["execution_error_class"] == "mcp_write_failed"
    assert episode["evidence_provenance"]["evidence_count"] == 2
