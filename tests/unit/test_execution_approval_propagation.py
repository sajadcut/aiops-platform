import pytest

from apps.execution_service import ExecutionRequest, ExecutionService
from apps.execution_service.tools.base import BaseTool, ToolInput, ToolResult
from apps.execution_service.tools.registry import tool_registry


class ApprovalRequiredTool(BaseTool):
    name = "approval_required_test"
    description = "Test-only approval-required execution tool"
    risk_level = "high"
    requires_approval = True

    async def validate(self, input_data: ToolInput) -> bool:
        return input_data.action == "restart_service" and bool(input_data.target)

    async def execute(self, input_data: ToolInput) -> ToolResult:
        return ToolResult(success=True, result={"executed": True})


@pytest.mark.asyncio
async def test_approved_request_reaches_tool_registry_with_approval_context():
    tool_registry.register(ApprovalRequiredTool())
    try:
        result = await ExecutionService.execute(
            ExecutionRequest(
                tool_name="approval_required_test",
                action="restart_service",
                target="vm01",
                approval_granted=True,
                approval_id="approval-123",
            )
        )
        assert result.success is True
        assert result.execution_blocked is False
        assert result.approval_id == "approval-123"
    finally:
        tool_registry.clear()


@pytest.mark.asyncio
async def test_approved_request_without_persisted_approval_id_is_blocked():
    tool_registry.register(ApprovalRequiredTool())
    try:
        result = await ExecutionService.execute(
            ExecutionRequest(
                tool_name="approval_required_test",
                action="restart_service",
                target="vm01",
                approval_granted=True,
            )
        )
        assert result.success is False
        assert result.execution_blocked is True
        assert result.reason == "approval_id_required"
    finally:
        tool_registry.clear()
