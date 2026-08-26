from __future__ import annotations

from apps.execution_service.tools.base import BaseTool, ToolInput, ToolOutput
from integrations.vm.mcp_client import VMEdgeMCPClient


class VMTelemetryTool(BaseTool):
    """Read-only VM telemetry tool backed by MCP Edge transport."""

    def __init__(self, connector: VMEdgeMCPClient | None = None):
        self.connector = connector

    def _connector(self) -> VMEdgeMCPClient:
        if self.connector is None:
            self.connector = VMEdgeMCPClient()
        return self.connector

    @property
    def name(self) -> str:
        return "vm_telemetry"

    @property
    def risk_level(self) -> str:
        return "low"

    @property
    def requires_approval(self) -> bool:
        return False

    async def validate(self, input_data: ToolInput) -> bool:
        return bool(input_data.target) and input_data.action in {"collect_vm_metrics", "service_status", "process_snapshot"}

    async def execute(self, input_data: ToolInput) -> ToolOutput:
        connector = self._connector()
        params = input_data.parameters or {}
        if input_data.action == "collect_vm_metrics":
            result = await connector.collect_metrics(input_data.target)
        elif input_data.action == "service_status":
            result = await connector.service_status(input_data.target, str(params.get("service", "")))
        else:
            result = await connector.process_snapshot(input_data.target)
        return ToolOutput(success=bool(result.get("success")), result=result, error=result.get("error"))
