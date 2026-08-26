from __future__ import annotations

from typing import Any, Dict, Optional

from domain.contracts.config import settings
from integrations.mcp_client import MCPClient


class VMEdgeMCPClient(MCPClient):
    """MCP-only connector for VM/Edge telemetry and allowlisted remediation."""

    def __init__(self, server_url: Optional[str] = None):
        url = server_url or settings.VM_MCP_URL
        if not url:
            raise ValueError("vm_mcp_url_not_configured")
        super().__init__(
            url,
            "vm-edge",
            allowed_tools={"collect_vm_metrics", "service_status", "process_snapshot", "restart_service"},
            protocol_version=settings.MCP_PROTOCOL_VERSION,
            timeout=settings.MCP_TIMEOUT_SECONDS,
            bearer_token=settings.MCP_BEARER_TOKEN,
            ca_cert_path=settings.MCP_CA_CERT_PATH,
            client_cert_path=settings.MCP_CLIENT_CERT_PATH,
            client_key_path=settings.MCP_CLIENT_KEY_PATH,
            require_https=settings.MCP_REQUIRE_HTTPS,
        )

    async def _invoke(self, name: str, target: str, **params: Any) -> Dict[str, Any]:
        result = await self.call_tool(name, {"target": target, **params})
        if isinstance(result.get("content"), list) and result["content"]:
            first = result["content"][0]
            if isinstance(first, dict):
                return first
        return result

    async def collect_metrics(self, target: str) -> Dict[str, Any]:
        return await self._invoke("collect_vm_metrics", target)

    async def service_status(self, target: str, service: str) -> Dict[str, Any]:
        return await self._invoke("service_status", target, service=service)

    async def process_snapshot(self, target: str) -> Dict[str, Any]:
        return await self._invoke("process_snapshot", target)

    async def restart_service(self, target: str, service: str) -> Dict[str, Any]:
        return await self._invoke("restart_service", target, service=service)
