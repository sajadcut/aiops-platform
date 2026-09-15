from __future__ import annotations

from apps.execution_service.tools.base import BaseTool, ToolInput, ToolOutput
from integrations.vm.mcp_client import VMEdgeMCPClient


class VMTelemetryTool(BaseTool):
    """Read-only VM diagnostic tool backed by the governed MCP edge transport."""

    _ACTIONS = set(VMEdgeMCPClient.READ_TOOLS)

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
        if not input_data.target or input_data.action not in self._ACTIONS:
            return False
        params = input_data.parameters or {}
        if input_data.action in {"service_status", "service_logs", "config_validate"}:
            return bool(str(params.get("service", "")).strip())
        if input_data.action == "process_status":
            return bool(str(params.get("process", "")).strip())
        if input_data.action in {"port_listener_status"}:
            return bool(params.get("port"))
        if input_data.action == "tcp_check":
            return bool(str(params.get("host", "")).strip()) and bool(params.get("port"))
        if input_data.action == "dns_check":
            return bool(str(params.get("hostname", "")).strip())
        if input_data.action == "route_check":
            return bool(str(params.get("destination", "")).strip())
        return True

    async def execute(self, input_data: ToolInput) -> ToolOutput:
        connector = self._connector()
        params = input_data.parameters or {}
        action = input_data.action
        target = input_data.target
        if action == "collect_vm_metrics": result = await connector.collect_vm_metrics(target)
        elif action == "host_info": result = await connector.host_info(target)
        elif action == "disk_status": result = await connector.disk_status(target)
        elif action == "network_status": result = await connector.network_status(target)
        elif action == "service_status": result = await connector.service_status(target, str(params["service"]))
        elif action == "service_logs": result = await connector.service_logs(target, str(params["service"]), int(params.get("limit", 100)))
        elif action == "system_logs": result = await connector.system_logs(target, int(params.get("limit", 100)))
        elif action == "process_snapshot": result = await connector.process_snapshot(target)
        elif action == "process_status": result = await connector.process_status(target, str(params["process"]))
        elif action == "tcp_check": result = await connector.tcp_check(target, str(params["host"]), int(params["port"]))
        elif action == "port_listener_status": result = await connector.port_listener_status(target, int(params["port"]))
        elif action == "dns_check": result = await connector.dns_check(target, str(params["hostname"]))
        elif action == "route_check": result = await connector.route_check(target, str(params["destination"]))
        elif action == "firewall_status": result = await connector.firewall_status(target)
        elif action == "config_validate": result = await connector.config_validate(target, str(params["service"]))
        else: result = {"success": False, "error": "unsupported_action"}
        return ToolOutput(success=bool(result.get("success")), result=result, error=result.get("error"))
