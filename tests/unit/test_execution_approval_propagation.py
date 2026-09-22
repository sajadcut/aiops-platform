import pytest

import apps.approval_service.execution_claim as claim_module
from apps.approval_service.execution_claim import issue_execution_claim
from apps.execution_service import ExecutionRequest, ExecutionService
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
async def test_validated_approval_context_reaches_tool_registry():
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
                execution_claim=issue_execution_claim(),
            )
        )
        assert result.success is True
        assert result.execution_blocked is False
        assert result.approval_id == "approval-123"
    finally:
        tool_registry.clear()


@pytest.mark.asyncio
async def test_approval_ids_without_granted_marker_are_blocked():
    tool_registry.register(ApprovalRequiredTool())
    try:
        result = await ExecutionService.execute(
            ExecutionRequest(
                tool_name="approval_required_test",
                action="restart_service",
                target="vm01",
                incident_id="incident-1",
                approval_granted=False,
                approval_id="approval-123",
            )
        )
        assert result.success is False
        assert result.execution_blocked is True
        assert result.reason == "approval_not_granted"
    finally:
        tool_registry.clear()


@pytest.mark.asyncio
async def test_granted_marker_without_bound_ids_is_blocked():
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


@pytest.mark.asyncio
async def test_boolean_and_approval_id_cannot_bypass_single_use_execution_claim():
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
        assert result.reason == "approval_execution_claim_invalid_or_replayed"
    finally:
        tool_registry.clear()


@pytest.mark.asyncio
async def test_execution_claim_is_redeemed_exactly_once():
    tool_registry.register(ApprovalRequiredTool())
    try:
        claim = issue_execution_claim()
        request = ExecutionRequest(
            tool_name="approval_required_test",
            action="restart_service",
            target="vm01",
            incident_id="incident-1",
            approval_granted=True,
            approval_id="approval-123",
            execution_claim=claim,
        )
        first = await ExecutionService.execute(request)
        second = await ExecutionService.execute(request)
        assert first.success is True
        assert second.success is False
        assert second.execution_blocked is True
        assert second.reason == "approval_execution_claim_invalid_or_replayed"
    finally:
        tool_registry.clear()


def test_execution_claim_expires_and_cannot_be_redeemed(monkeypatch):
    claim_module._ISSUED.clear()
    clock = {"now": 100.0}
    monkeypatch.setattr(claim_module, "monotonic", lambda: clock["now"])
    monkeypatch.setattr(claim_module, "_ttl_seconds", lambda: 5.0)

    claim = claim_module.issue_execution_claim()
    clock["now"] = 106.0

    assert claim_module.redeem_execution_claim(claim) is False
    assert claim not in claim_module._ISSUED
