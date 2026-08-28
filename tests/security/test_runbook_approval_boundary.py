import pytest

from apps.execution_service import ExecutionResult, ExecutionService
from apps.runbook_service.executor import RunbookExecutor


class _Registry:
    def get(self, runbook_id):
        return {"id": runbook_id, "version": "1", "action": "restart_service"}

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


@pytest.mark.asyncio
async def test_non_empty_approval_id_does_not_grant_execution(monkeypatch):
    captured = {}

    async def fake_execute(request):
        captured["approval_granted"] = request.approval_granted
        captured["approval_id"] = request.approval_id
        return _result(success=False, blocked=True)

    monkeypatch.setattr(ExecutionService, "execute", fake_execute)
    executor = RunbookExecutor(_Registry())
    await executor.execute(
        "restart-service",
        tool_name="ssh_vm",
        target="vm01",
        parameters={"service": "nginx"},
        approval_id="random-unvalidated-id",
    )
    assert captured["approval_granted"] is False
    assert captured["approval_id"] is None


@pytest.mark.asyncio
async def test_validated_caller_must_explicitly_grant_approval(monkeypatch):
    captured = {}

    async def fake_execute(request):
        captured["approval_granted"] = request.approval_granted
        captured["approval_id"] = request.approval_id
        return _result(success=True, blocked=False)

    monkeypatch.setattr(ExecutionService, "execute", fake_execute)
    executor = RunbookExecutor(_Registry())
    await executor.execute(
        "restart-service",
        tool_name="ssh_vm",
        target="vm01",
        parameters={"service": "nginx"},
        approval_id="validated-id",
        approval_granted=True,
    )
    assert captured["approval_granted"] is True
    assert captured["approval_id"] == "validated-id"
