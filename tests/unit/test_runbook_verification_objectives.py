import pytest

from apps.orchestrator.e2e_graph import E2EOrchestrator
from apps.verification_service import VerificationEngine, VerificationStatus


def _context(*, service_active=None, port_listening=None):
    evidence = []
    if service_active is not None:
        evidence.append(
            {
                "reference": f"svc-{service_active}",
                "source": "vm_mcp",
                "raw_data": {
                    "diagnostic": "service_status",
                    "active_state": "active" if service_active else "inactive",
                },
            }
        )
    if port_listening is not None:
        evidence.append(
            {
                "reference": f"port-{port_listening}",
                "source": "vm_mcp",
                "raw_data": {
                    "diagnostic": "port_listener_status",
                    "listening": bool(port_listening),
                },
            }
        )
    return {"live_evidence": {"evidence": evidence}}


VM_OBJECTIVES = [
    {"state": "service_active", "direction": "equals", "expected": True},
    {"state": "port_listening", "direction": "equals", "expected": True},
]


@pytest.mark.asyncio
async def test_runbook_objectives_fail_when_required_post_state_is_unhealthy():
    result = await VerificationEngine.verify_action(
        "start nginx",
        "nginx",
        _context(service_active=False, port_listening=False),
        _context(service_active=True, port_listening=False),
        verification_objectives=VM_OBJECTIVES,
    )

    assert result.status == VerificationStatus.FAILED
    assert result.verification_policy == "runbook_required_objectives"
    assert result.required_objectives_met is False
    by_target = {item["target"]: item for item in result.objective_results}
    assert by_target["service_active"]["passed"] is True
    assert by_target["port_listening"]["passed"] is False


@pytest.mark.asyncio
async def test_runbook_objectives_are_fail_closed_when_required_evidence_is_missing():
    result = await VerificationEngine.verify_action(
        "start nginx",
        "nginx",
        _context(service_active=False, port_listening=False),
        _context(service_active=True),
        verification_objectives=VM_OBJECTIVES,
    )

    assert result.status == VerificationStatus.INCONCLUSIVE
    assert result.required_objectives_met is False
    by_target = {item["target"]: item for item in result.objective_results}
    assert by_target["port_listening"]["reason"] == (
        "post_execution_objective_evidence_missing"
    )


@pytest.mark.asyncio
async def test_orchestrator_uses_registered_runbook_verification_objectives(monkeypatch):
    orchestrator = E2EOrchestrator.__new__(E2EOrchestrator)

    monkeypatch.setattr(
        E2EOrchestrator,
        "_audit",
        staticmethod(lambda *args, **kwargs: None),
    )

    state = {
        "service_name": "nginx",
        "final_plan": "Use governed start_service and verify recovery.",
        "execution_request": {
            "tool_name": "ssh_vm",
            "action": "start_service",
            "target": "10.100.6.199",
            "parameters": {"service": "nginx"},
            "runbook_id": "vm-service-recovery",
            "runbook_version": "1.1",
        },
        "before_context": _context(
            service_active=False,
            port_listening=False,
        ),
        "after_context": _context(
            service_active=True,
            port_listening=True,
        ),
        "context": {},
    }

    result = await orchestrator._verification_node(state)

    verification = result["verification_result"]
    assert verification["status"] == "success"
    assert verification["runbook_id"] == "vm-service-recovery"
    assert verification["verification_window_seconds"] == 120
    assert verification["required_objectives_met"] is True
    assert {item["target"] for item in verification["objective_results"]} == {
        "service_active",
        "port_listening",
    }


@pytest.mark.asyncio
async def test_orchestrator_fails_closed_when_runbook_contract_is_unavailable(monkeypatch):
    orchestrator = E2EOrchestrator.__new__(E2EOrchestrator)

    monkeypatch.setattr(
        E2EOrchestrator,
        "_audit",
        staticmethod(lambda *args, **kwargs: None),
    )

    state = {
        "service_name": "nginx",
        "final_plan": "recover",
        "execution_request": {
            "tool_name": "ssh_vm",
            "action": "start_service",
            "target": "10.100.6.199",
            "parameters": {"service": "nginx"},
            "runbook_id": "missing-runbook",
            "runbook_version": "1",
        },
        "before_context": _context(
            service_active=False,
            port_listening=False,
        ),
        "after_context": _context(
            service_active=True,
            port_listening=True,
        ),
        "context": {},
    }

    result = await orchestrator._verification_node(state)

    verification = result["verification_result"]
    assert verification["status"] == "inconclusive"
    assert verification["verification_policy"] == "runbook_contract_unavailable"
    assert verification["required_objectives_met"] is False
    assert verification["verification_contract_error"] is not None
