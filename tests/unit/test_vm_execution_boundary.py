import pytest

from apps.execution_service.tools.base import ToolInput
from apps.execution_service.tools.ssh_vm import SSHVMTool
from apps.execution_service.tools.vm_telemetry import VMTelemetryTool


@pytest.mark.asyncio
async def test_ssh_vm_tool_allows_only_governed_actions():
    tool = SSHVMTool()
    assert not await tool.validate(ToolInput(action="restart_service", target="vm01", parameters={"service": "nginx"}))
    assert not await tool.validate(ToolInput(
        action="restart_service", target="vm01", parameters={"service": "nginx"}, approval_id="approval-123"
    ))
    assert await tool.validate(ToolInput(
        action="restart_service",
        target="vm01",
        parameters={"service": "nginx"},
        incident_id="incident-1",
        approval_id="approval-123",
        execution_capability="signed-capability-placeholder",
    ))
    assert not await tool.validate(ToolInput(action="shell", target="vm01", parameters={"command": "rm -rf /"}))


@pytest.mark.asyncio
async def test_telemetry_tool_is_read_only():
    tool = VMTelemetryTool()
    assert tool.requires_approval is False
    assert await tool.validate(ToolInput(action="collect_vm_metrics", target="vm01"))
    assert not await tool.validate(ToolInput(action="restart_service", target="vm01", parameters={"service": "nginx"}))
