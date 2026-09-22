import pytest
from fastapi import HTTPException

from apps.api.runbook_execution import _runbook_contract
from apps.runbook_service.executor import RunbookExecutor
from apps.runbook_service.registry import RunbookRegistry


def test_vm_recovery_contract_derives_tool_and_requires_allowlisted_action():
    runbook, tool, action, target, parameters, timeout, rollback = _runbook_contract(
        "vm-service-recovery",
        {
            "action": "start_service",
            "target": "10.100.6.199",
            "parameters": {"service": "nginx"},
        },
    )

    assert runbook["id"] == "vm-service-recovery"
    assert tool == "ssh_vm"
    assert action == "start_service"
    assert target == "10.100.6.199"
    assert parameters == {"service": "nginx"}
    assert timeout == 30
    assert rollback is False


def test_vm_recovery_contract_rejects_caller_tool_override():
    with pytest.raises(HTTPException) as exc:
        _runbook_contract(
            "vm-service-recovery",
            {
                "tool_name": "kubernetes_mcp",
                "action": "start_service",
                "target": "10.100.6.199",
                "parameters": {"service": "nginx"},
            },
        )

    assert exc.value.status_code == 409
    assert exc.value.detail == "runbook_tool_mismatch"


def test_vm_recovery_contract_rejects_action_outside_runbook_allowlist():
    with pytest.raises(HTTPException) as exc:
        _runbook_contract(
            "vm-service-recovery",
            {
                "action": "reload_service",
                "target": "10.100.6.199",
                "parameters": {"service": "nginx"},
            },
        )

    assert exc.value.status_code == 409
    assert exc.value.detail == "runbook_action_not_allowed"


@pytest.mark.asyncio
async def test_runbook_executor_enforces_contract_even_when_called_without_api():
    executor = RunbookExecutor(RunbookRegistry("runbooks"))

    valid = await executor.execute(
        "vm-service-recovery",
        tool_name="ssh_vm",
        action="restart_service",
        target="10.100.6.199",
        parameters={"service": "nginx"},
        dry_run=True,
    )
    assert valid["status"] == "dry_run"
    assert valid["action"] == "restart_service"

    with pytest.raises(ValueError, match="runbook_tool_mismatch"):
        await executor.execute(
            "vm-service-recovery",
            tool_name="kubernetes_mcp",
            action="restart_service",
            target="10.100.6.199",
            parameters={"service": "nginx"},
            dry_run=True,
        )

    with pytest.raises(ValueError, match="runbook_action_not_allowed"):
        await executor.execute(
            "vm-service-recovery",
            tool_name="ssh_vm",
            action="reload_service",
            target="10.100.6.199",
            parameters={"service": "nginx"},
            dry_run=True,
        )
