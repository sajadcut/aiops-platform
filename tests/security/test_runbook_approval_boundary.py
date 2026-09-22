import pytest

from apps.approval_service.binding import bind_metadata
from apps.approval_service.execution_claim import issue_execution_claim
from apps.execution_service import ExecutionResult, ExecutionService
from apps.runbook_service.executor import RunbookExecutor


class _Registry:
    def get(self, runbook_id):
        return {
            "id": runbook_id,
            "version": "1",
            "action": "restart_service",
            "execution": {
                "tool": "ssh_vm",
                "allowed_actions": ["restart_service"],
            },
        }

    def validate(self, runbook_id, parameters):
        return {"valid": True}


def _result(*, success: bool, blocked: bool):
    return ExecutionResult(
        success=success,
        tool_name="ssh_vm",
        action="restart_service",
        target="vm01",
        execution_blocked=blocked,
        reason="approval_required" if blocked else None,
        result={} if success else None,
    )


def _consumed_context(approval_id: str) -> dict:
    incident_id = "incident-1"
    metadata = bind_metadata(
        {},
        incident_id=incident_id,
        tool_name="ssh_vm",
        action="restart_service",
        target="vm01",
        parameters={"service": "nginx"},
        timeout=30,
        runbook_id="restart-service",
        runbook_version="1",
        rollback=False,
    )
    return {
        "approval_id": approval_id,
        "incident_id": incident_id,
        "action": "restart_service",
        "status": "consumed",
        "metadata": metadata,
        "_execution_claim": issue_execution_claim(),
    }


@pytest.mark.asyncio
async def test_plain_approval_boolean_and_id_do_not_grant_execution(monkeypatch):
    calls = []

    async def fake_execute(request):
        calls.append(request)
        return _result(success=True, blocked=False)

    monkeypatch.setattr(ExecutionService, "execute", fake_execute)
    executor = RunbookExecutor(_Registry())

    with pytest.raises(ValueError, match="runbook_execution_claim_required"):
        await executor.execute(
            "restart-service",
            tool_name="ssh_vm",
            target="vm01",
            parameters={"service": "nginx"},
            incident_id="incident-1",
            approval_id="random-unvalidated-id",
            approval_granted=True,
        )

    assert calls == []


@pytest.mark.asyncio
async def test_consumed_bound_execution_claim_is_propagated_once(monkeypatch):
    captured = {}

    async def fake_execute(request):
        captured["approval_granted"] = request.approval_granted
        captured["approval_id"] = request.approval_id
        captured["incident_id"] = request.incident_id
        return _result(success=True, blocked=False)

    monkeypatch.setattr(ExecutionService, "execute", fake_execute)
    executor = RunbookExecutor(_Registry())
    context = _consumed_context("validated-id")

    result = await executor.execute(
        "restart-service",
        tool_name="ssh_vm",
        target="vm01",
        parameters={"service": "nginx"},
        incident_id="incident-1",
        approval_id="validated-id",
        approval_context=context,
    )

    assert result["status"] == "executed"
    assert captured["approval_granted"] is True
    assert captured["approval_id"] == "validated-id"
    assert captured["incident_id"] == "incident-1"


@pytest.mark.asyncio
async def test_replay_cache_is_scoped_to_same_consumed_approval(monkeypatch):
    calls = []

    async def fake_execute(request):
        calls.append(request.approval_id)
        return _result(success=True, blocked=False)

    monkeypatch.setattr(ExecutionService, "execute", fake_execute)
    executor = RunbookExecutor(_Registry())
    first_context = _consumed_context("approval-1")

    first = await executor.execute(
        "restart-service",
        tool_name="ssh_vm",
        target="vm01",
        parameters={"service": "nginx"},
        incident_id="incident-1",
        approval_id="approval-1",
        approval_context=first_context,
    )
    replay = await executor.execute(
        "restart-service",
        tool_name="ssh_vm",
        target="vm01",
        parameters={"service": "nginx"},
        incident_id="incident-1",
        approval_id="approval-1",
        approval_context=first_context,
    )
    second_context = _consumed_context("approval-2")
    second_authority = await executor.execute(
        "restart-service",
        tool_name="ssh_vm",
        target="vm01",
        parameters={"service": "nginx"},
        incident_id="incident-1",
        approval_id="approval-2",
        approval_context=second_context,
    )

    assert first["status"] == "executed"
    assert replay["status"] == "idempotent_replay"
    assert second_authority["status"] == "executed"
    assert calls == ["approval-1", "approval-2"]


@pytest.mark.asyncio
async def test_consumed_claim_cannot_be_replayed_through_new_executor(monkeypatch):
    calls = []

    real_execute = ExecutionService.execute

    async def fake_tool_execute(_request):
        return _result(success=True, blocked=False)

    async def execute_through_claim_boundary(request):
        calls.append(request.approval_id)
        if not request.execution_claim:
            return _result(success=False, blocked=True)
        from apps.approval_service.execution_claim import redeem_execution_claim
        if not redeem_execution_claim(request.execution_claim):
            return _result(success=False, blocked=True)
        return await fake_tool_execute(request)

    monkeypatch.setattr(ExecutionService, "execute", execute_through_claim_boundary)
    context = _consumed_context("approval-1")

    await RunbookExecutor(_Registry()).execute(
        "restart-service",
        tool_name="ssh_vm",
        target="vm01",
        parameters={"service": "nginx"},
        incident_id="incident-1",
        approval_id="approval-1",
        approval_context=context,
    )

    replay = await RunbookExecutor(_Registry()).execute(
        "restart-service",
        tool_name="ssh_vm",
        target="vm01",
        parameters={"service": "nginx"},
        incident_id="incident-1",
        approval_id="approval-1",
        approval_context=context,
    )

    assert replay["status"] == "executed"
    assert replay["result"]["success"] is False
    assert replay["result"]["execution_blocked"] is True
    # The fake boundary used by this test returns a generic blocked result;
    # the important invariant is that the second executor cannot produce a
    # successful write from the already-redeemed claim.
    assert calls == ["approval-1", "approval-1"]

