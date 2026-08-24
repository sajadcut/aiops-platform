from __future__ import annotations

from apps.execution_service.tools.base import BaseTool, ToolInput, ToolOutput
from integrations.vm.ssh_connector import SSHVMConnector


class SSHVMTool(BaseTool):
    """Governed Linux VM tool for telemetry and approved remediation."""

    def __init__(self, connector: SSHVMConnector | None = None):
        self.connector = connector or SSHVMConnector()

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
        if not input_data.target or input_data.action not in {
            "collect_vm_metrics",
            "service_status",
            "restart_service",
            "process_snapshot",
        }:
            return False
        if input_data.action in {"service_status", "restart_service"}:
            service = str((input_data.parameters or {}).get("service", ""))
            if not service:
                return False
        return True

    async def execute(self, input_data: ToolInput) -> ToolOutput:
        params = input_data.parameters or {}
        if input_data.action == "collect_vm_metrics":
            result = await self.connector.collect_metrics(input_data.target)
        elif input_data.action == "service_status":
            result = await self.connector.service_status(input_data.target, str(params["service"]))
        elif input_data.action == "restart_service":
            result = await self.connector.restart_service(input_data.target, str(params["service"]))
        elif input_data.action == "process_snapshot":
            result = await self.connector.process_snapshot(input_data.target)
        else:
            result = {"success": False, "error": "unsupported_action"}
        return ToolOutput(
            success=bool(result.get("success")),
            result=result,
            error=result.get("error"),
        )
