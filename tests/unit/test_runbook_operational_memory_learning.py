import pytest

import apps.runbook_service.learning as learning


def _kwargs(*, execution_success: bool, verification_status: str, evidence=None):
    return {
        "incident_id": "11111111-1111-1111-1111-111111111111",
        "runbook": {"id": "vm-service-recovery", "version": "1.1", "risk": "high"},
        "tool_name": "ssh_vm",
        "action": "start_service",
        "target": "10.0.0.10",
        "parameters": {"service": "nginx"},
        "approval": {
            "approval_id": "22222222-2222-2222-2222-222222222222",
            "status": "consumed",
        },
        "execution_result": {
            "success": execution_success,
            "reason": None if execution_success else "remote_action_failed",
        },
        "verification_result": {
            "status": verification_status,
            "required_objectives_met": verification_status == "success",
        },
        "before_snapshot": {"evidence": list(evidence or [])},
        "after_snapshot": {"evidence": []},
    }


@pytest.mark.asyncio
async def test_failed_governed_runbook_is_learned_even_without_snapshot_evidence(monkeypatch):
    captured = {}

    async def add_episode(_self, episode):
        captured["episode"] = episode
        return "33333333-3333-3333-3333-333333333333"

    monkeypatch.setattr(learning.OperationalMemoryService, "add_episode", add_episode)

    memory_id = await learning.record_runbook_outcome(
        object(),
        **_kwargs(execution_success=False, verification_status="failed"),
    )

    assert memory_id == "33333333-3333-3333-3333-333333333333"
    assert captured["episode"]["actual_remediation"]["execution_success"] is False


@pytest.mark.asyncio
async def test_successful_runbook_without_evidence_is_not_promoted_to_reusable_memory(monkeypatch):
    called = False

    async def add_episode(_self, _episode):
        nonlocal called
        called = True
        return "unexpected"

    monkeypatch.setattr(learning.OperationalMemoryService, "add_episode", add_episode)

    memory_id = await learning.record_runbook_outcome(
        object(),
        **_kwargs(execution_success=True, verification_status="success"),
    )

    assert memory_id is None
    assert called is False


@pytest.mark.asyncio
async def test_successful_runbook_with_evidence_is_persisted(monkeypatch):
    async def add_episode(_self, _episode):
        return "44444444-4444-4444-4444-444444444444"

    monkeypatch.setattr(learning.OperationalMemoryService, "add_episode", add_episode)

    memory_id = await learning.record_runbook_outcome(
        object(),
        **_kwargs(
            execution_success=True,
            verification_status="success",
            evidence=[{"id": "live-1", "source": "vm_mcp", "type": "service_state"}],
        ),
    )

    assert memory_id == "44444444-4444-4444-4444-444444444444"
