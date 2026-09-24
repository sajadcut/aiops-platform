import pytest

from apps.execution_service.tools.base import BaseTool, ToolInput
from apps.execution_service.tools.registry import tool_registry


class _DeniedReadTool(BaseTool):
    @property
    def name(self) -> str:
        return "denied_read"

    @property
    def risk_level(self) -> str:
        return "low"

    async def execute(self, input_data: ToolInput):
        raise PermissionError("vm_target_not_allowed")


class _UnknownDeniedReadTool(_DeniedReadTool):
    async def execute(self, input_data: ToolInput):
        raise PermissionError("provider_internal_permission_detail")


@pytest.mark.asyncio
async def test_execution_registry_preserves_safe_vm_policy_denial(monkeypatch):
    tool = _DeniedReadTool()
    monkeypatch.setattr(tool_registry, "get_tool", lambda name: tool if name == tool.name else None)

    result = await tool_registry.execute_tool(
        tool_name=tool.name,
        input_data=ToolInput(action="service_status", target="10.100.6.200"),
        agent_name="chatbot",
    )

    assert result["success"] is False
    assert result["execution_blocked"] is True
    assert result["reason"] == "vm_target_not_allowed"
    assert result["error"] == "vm_target_not_allowed"


@pytest.mark.asyncio
async def test_execution_registry_redacts_unknown_permission_denial(monkeypatch):
    tool = _UnknownDeniedReadTool()
    monkeypatch.setattr(tool_registry, "get_tool", lambda name: tool if name == tool.name else None)

    result = await tool_registry.execute_tool(
        tool_name=tool.name,
        input_data=ToolInput(action="service_status", target="10.100.6.200"),
        agent_name="chatbot",
    )

    assert result["success"] is False
    assert result["execution_blocked"] is True
    assert result["reason"] == "permission_denied"
    assert result["error"] == "permission_denied"
    assert "internal" not in str(result)
