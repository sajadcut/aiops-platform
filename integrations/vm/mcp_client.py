from __future__ import annotations

from typing import Any, Dict, Optional

from domain.contracts.config import settings
from integrations.mcp_client import MCPClient


class VMEdgeMCPClient(MCPClient):
    """MCP-only connector for VM/Edge diagnostics and governed remediation."""

    READ_TOOLS = {
        "collect_vm_metrics", "host_info", "disk_status", "network_status",
        "service_status", "service_logs", "system_logs", "process_snapshot",
        "process_status", "tcp_check", "port_listener_status", "dns_check",
        "route_check", "firewall_status", "config_validate",
    }
    WRITE_TOOLS = {"restart_service", "reload_service", "start_service"}

    def __init__(self, server_url: Optional[str] = None):
        url = server_url or settings.VM_MCP_URL
        if not url:
            raise ValueError("vm_mcp_url_not_configured")
        super().__init__(
            url, "vm-edge", allowed_tools=self.READ_TOOLS | self.WRITE_TOOLS,
            write_tools=self.WRITE_TOOLS, protocol_version=settings.MCP_PROTOCOL_VERSION,
            timeout=settings.MCP_TIMEOUT_SECONDS, bearer_token=settings.MCP_BEARER_TOKEN,
            write_bearer_token=settings.MCP_WRITE_BEARER_TOKEN,
            client_cert_path=settings.MCP_CLIENT_CERT_PATH,
            client_key_path=settings.MCP_CLIENT_KEY_PATH,
        )

    async def _invoke(self, name: str, target: str, **params: Any) -> Dict[str, Any]:
        result = await self.call_tool(name, {"target": target, **params})
        if isinstance(result.get("content"), list) and result["content"]:
            first = result["content"][0]
            if isinstance(first, dict):
                return first
        return result

    async def collect_vm_metrics(self, target: str) -> Dict[str, Any]: return await self._invoke("collect_vm_metrics", target)
    async def collect_metrics(self, target: str) -> Dict[str, Any]: return await self.collect_vm_metrics(target)
    async def host_info(self, target: str) -> Dict[str, Any]: return await self._invoke("host_info", target)
    async def disk_status(self, target: str) -> Dict[str, Any]: return await self._invoke("disk_status", target)
    async def network_status(self, target: str) -> Dict[str, Any]: return await self._invoke("network_status", target)
    async def service_status(self, target: str, service: str) -> Dict[str, Any]: return await self._invoke("service_status", target, service=service)
    async def service_logs(self, target: str, service: str, limit: int = 30) -> Dict[str, Any]: return await self._invoke("service_logs", target, service=service, limit=limit)
    async def system_logs(self, target: str, limit: int = 50) -> Dict[str, Any]: return await self._invoke("system_logs", target, limit=limit)
    async def process_snapshot(self, target: str) -> Dict[str, Any]: return await self._invoke("process_snapshot", target)
    async def process_status(self, target: str, process: str) -> Dict[str, Any]: return await self._invoke("process_status", target, process=process)
    async def tcp_check(self, target: str, host: str, port: int) -> Dict[str, Any]: return await self._invoke("tcp_check", target, host=host, port=port)
    async def port_listener_status(self, target: str, port: int) -> Dict[str, Any]: return await self._invoke("port_listener_status", target, port=port)
    async def dns_check(self, target: str, hostname: str) -> Dict[str, Any]: return await self._invoke("dns_check", target, hostname=hostname)
    async def route_check(self, target: str, destination: str) -> Dict[str, Any]: return await self._invoke("route_check", target, destination=destination)
    async def firewall_status(self, target: str) -> Dict[str, Any]: return await self._invoke("firewall_status", target)
    async def config_validate(self, target: str, service: str) -> Dict[str, Any]: return await self._invoke("config_validate", target, service=service)

    @staticmethod
    def _write_context(approval_id: str, incident_id: str, execution_capability: str) -> Dict[str, str]:
        if not approval_id: raise PermissionError("mcp_write_approval_id_required")
        if not incident_id: raise PermissionError("mcp_write_incident_id_required")
        if not execution_capability: raise PermissionError("mcp_write_execution_capability_required")
        return {"approval_id": approval_id, "incident_id": incident_id, "execution_capability": execution_capability}

    async def restart_service(self, target: str, service: str, approval_id: str, incident_id: str, execution_capability: str) -> Dict[str, Any]:
        return await self._invoke("restart_service", target, service=service, **self._write_context(approval_id, incident_id, execution_capability))

    async def reload_service(self, target: str, service: str, approval_id: str, incident_id: str, execution_capability: str) -> Dict[str, Any]:
        return await self._invoke("reload_service", target, service=service, **self._write_context(approval_id, incident_id, execution_capability))

    async def start_service(self, target: str, service: str, approval_id: str, incident_id: str, execution_capability: str) -> Dict[str, Any]:
        return await self._invoke("start_service", target, service=service, **self._write_context(approval_id, incident_id, execution_capability))
