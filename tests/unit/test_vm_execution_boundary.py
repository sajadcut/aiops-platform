import pytest

from apps.execution_service.tools.base import ToolInput
from apps.execution_service.tools.ssh_vm import SSHVMTool
from apps.execution_service.tools.vm_telemetry import VMTelemetryTool


@pytest.mark.asyncio
async def test_ssh_vm_tool_allows_only_governed_actions():
    tool = SSHVMTool()
    # Mutations are invalid at the tool boundary without the approval reference
    # produced by the central Decision/Approval path.
    assert not await tool.validate(ToolInput(action="restart_service", target="vm01", parameters={"service": "nginx"}))
    assert await tool.validate(ToolInput(action="restart_service", target="vm01", parameters={"service": "nginx"}, approval_id="approval-123"))
    assert not await tool.validate(ToolInput(action="shell", target="vm01", parameters={"command": "rm -rf /"}))


@pytest.mark.asyncio
async def test_telemetry_tool_is_read_only():
    tool = VMTelemetryTool()
    assert tool.requires_approval is False
    assert await tool.validate(ToolInput(action="collect_vm_metrics", target="vm01"))
    assert not await tool.validate(ToolInput(action="restart_service", target="vm01", parameters={"service": "nginx"}))
