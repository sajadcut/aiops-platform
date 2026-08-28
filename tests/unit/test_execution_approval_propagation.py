import pytest

from apps.execution_service import ExecutionRequest, ExecutionService
from apps.execution_service.capability import issue_execution_capability
from apps.execution_service.tools.base import BaseTool, ToolInput, ToolOutput
from apps.execution_service.tools.registry import tool_registry


class ApprovalRequiredTool(BaseTool):
    @property
    def name(self) -> str:
        return "approval_required_test"

    @property
    def risk_level(self) -> str:
        return "high"

    async def validate(self, input_data: ToolInput) -> bool:
        return input_data.action == "restart_service" and bool(input_data.target)

    async def execute(self, input_data: ToolInput) -> ToolOutput:
        return ToolOutput(success=True, result={"executed": True})


@pytest.mark.asyncio
async def test_signed_capability_reaches_tool_registry(monkeypatch):
    monkeypatch.setenv("EXECUTION_CAPABILITY_SECRET", "test-execution-capability-secret-32-bytes-minimum")
    tool_registry.register(ApprovalRequiredTool())
    try:
        capability = issue_execution_capability(
            incident_id="incident-1",
            approval_id="approval-123",
            tool_name="approval_required_test",
            action="restart_service",
            target="vm01",
            parameters={},
            timeout=30,
        )
        result = await ExecutionService.execute(
            ExecutionRequest(
                tool_name="approval_required_test",
                action="restart_service",
                target="vm01",
                incident_id="incident-1",
                approval_granted=False,
                approval_id="approval-123",
                execution_capability=capability,
            )
        )
        assert result.success is True
        assert result.execution_blocked is False
        assert result.approval_id == "approval-123"
    finally:
        tool_registry.clear()


@pytest.mark.asyncio
async def test_forged_approval_boolean_without_capability_is_blocked():
    tool_registry.register(ApprovalRequiredTool())
    try:
        result = await ExecutionService.execute(
            ExecutionRequest(
                tool_name="approval_required_test",
                action="restart_service",
                target="vm01",
                incident_id="incident-1",
                approval_granted=True,
                approval_id="approval-123",
            )
        )
        assert result.success is False
        assert result.execution_blocked is True
        assert result.reason == "execution_capability_required"
    finally:
        tool_registry.clear()


@pytest.mark.asyncio
async def test_capability_is_bound_to_target_and_parameters(monkeypatch):
    monkeypatch.setenv("EXECUTION_CAPABILITY_SECRET", "test-execution-capability-secret-32-bytes-minimum")
    tool_registry.register(ApprovalRequiredTool())
    try:
        capability = issue_execution_capability(
            incident_id="incident-1",
            approval_id="approval-123",
            tool_name="approval_required_test",
            action="restart_service",
            target="vm01",
            parameters={"service": "api"},
            timeout=30,
        )
        result = await ExecutionService.execute(
            ExecutionRequest(
                tool_name="approval_required_test",
                action="restart_service",
                target="vm02",
                parameters={"service": "api"},
                incident_id="incident-1",
                approval_granted=True,
                approval_id="approval-123",
                execution_capability=capability,
            )
        )
        assert result.success is False
        assert result.reason == "execution_capability_invalid"
    finally:
        tool_registry.clear()
