from __future__ import annotations

from apps.execution_service.tools.base import BaseTool, ToolInput, ToolOutput
from integrations.vm.mcp_client import VMEdgeMCPClient


class SSHVMTool(BaseTool):
    """Backward-compatible governed VM tool backed by MCP Edge transport.

    The public tool name remains ``ssh_vm`` so existing runbooks/approvals keep
    working, but the Control Plane no longer opens SSH sessions itself.
    """

    def __init__(self, connector: VMEdgeMCPClient | None = None):
        self.connector = connector

    def _connector(self) -> VMEdgeMCPClient:
        if self.connector is None:
            self.connector = VMEdgeMCPClient()
        return self.connector

    @property
    def name(self) -> str:
        return "ssh_vm"

    @property
    def risk_level(self) -> str:
        return "high"

    @property
    def requires_approval(self) -> bool:
        return True

    async def validate(self, input_data: ToolInput) -> bool:
        if not input_data.target or input_data.action not in {"collect_vm_metrics", "service_status", "restart_service", "process_snapshot"}:
            return False
        if input_data.action in {"service_status", "restart_service"} and not str((input_data.parameters or {}).get("service", "")):
            return False
        return True

    async def execute(self, input_data: ToolInput) -> ToolOutput:
        connector = self._connector()
        params = input_data.parameters or {}
        if input_data.action == "collect_vm_metrics":
            result = await connector.collect_metrics(input_data.target)
        elif input_data.action == "service_status":
            result = await connector.service_status(input_data.target, str(params["service"]))
        elif input_data.action == "restart_service":
            result = await connector.restart_service(input_data.target, str(params["service"]))
        elif input_data.action == "process_snapshot":
            result = await connector.process_snapshot(input_data.target)
        else:
            result = {"success": False, "error": "unsupported_action"}
        return ToolOutput(success=bool(result.get("success")), result=result, error=result.get("error"))
