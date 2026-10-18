from __future__ import annotations

from typing import Any, Dict, Optional

from domain.contracts.config import settings
from integrations.mcp_client import MCPClient


def vm_transport_configured() -> bool:
    """A selected VM backend is configured; no implicit fallback to SSH."""
    return bool(settings.VM_AGENT_ENDPOINTS) if settings.VM_EXECUTION_BACKEND == "agent" else bool(settings.VM_MCP_URL)


class VMEdgeMCPClient(MCPClient):
    """MCP-only connector for VM/Edge diagnostics and governed remediation."""

    EXPECTED_SERVER_NAME = "aiops-vm-mcp"

    READ_TOOLS = {
        "collect_vm_metrics", "memory_diagnostics", "host_info", "disk_status", "disk_forensics", "network_status",
        "service_status", "service_logs", "system_logs", "process_snapshot",
        "process_status", "tcp_check", "port_listener_status", "dns_check",
        "route_check", "firewall_status", "config_validate", "nginx_config_review", "nginx_config_inspect",
        "service_runtime_discovery", "service_config_discovery", "service_config_review", "service_config_llm_repair", "dotnet_config_syntax",
        "config_change_validate",
    }
    WRITE_TOOLS = {"restart_service", "reload_service", "start_service", "config_change_apply"}

    def __init__(self, server_url: Optional[str] = None):
        self._backend = settings.VM_EXECUTION_BACKEND
        # An explicit server_url is a pinned endpoint used by the agent router.
        # The default client routes EACH operation based on its exact target.
        self._endpoint_direct = server_url is not None
        if self._backend == "agent":
            if not settings.VM_AGENT_ENDPOINTS:
                raise ValueError("vm_agent_endpoints_not_configured")
            url = server_url or next(iter(settings.VM_AGENT_ENDPOINTS.values()))
            self.EXPECTED_SERVER_NAME = "aiops-vm-agent-mcp"
        else:
            url = server_url or settings.VM_MCP_URL
        if not url:
            raise ValueError("vm_mcp_url_not_configured")
        self._identity_validated = False
        super().__init__(
            url, "vm-edge", allowed_tools=self.READ_TOOLS | self.WRITE_TOOLS,
            write_tools=self.WRITE_TOOLS, protocol_version=settings.MCP_PROTOCOL_VERSION,
            timeout=settings.MCP_TIMEOUT_SECONDS, bearer_token=settings.MCP_BEARER_TOKEN,
            write_bearer_token=settings.MCP_BEARER_TOKEN,
            client_cert_path=settings.MCP_CLIENT_CERT_PATH,
            client_key_path=settings.MCP_CLIENT_KEY_PATH,
            verify_tls=self._backend == "agent",
            tls_ca_bundle_path=settings.VM_AGENT_CA_BUNDLE_PATH if self._backend == "agent" else None,
        )
        # Full-file repair runs a bounded LLM call on the trusted MCP worker.
        # Use one longer read, not three 20-second HTTP retries: a lost
        # response does not cancel the in-flight remote LLM generation.
        # Config prevalidation and apply can rebuild a complete file, run
        # isolated vendor validation, then perform a bounded two-stage sudo
        # transaction. The generic 15/20-second MCP read timeout cancels the
        # HTTP request while the SSH command is still running. A write response
        # lost in this window is ambiguous and MUST NOT be blindly replayed.
        # Validation is a single read attempt to avoid parallel workers
        # reconstructing the same candidate after a slow response.
        self.single_attempt_read_tools = frozenset({
            "service_config_llm_repair", "config_change_validate",
        })
        self.tool_timeout_seconds = {
            "service_config_llm_repair": 140.0,
            "config_change_validate": 180.0,
            "config_change_apply": 180.0,
        }

    async def initialize(self) -> Dict[str, Any]:
        if self._initialized and self._identity_validated:
            return {"protocolVersion": self.negotiated_protocol_version}
        init_result = await super().initialize()
        server_info = init_result.get("serverInfo") if isinstance(init_result, dict) else None
        actual_name = str((server_info or {}).get("name") or "").strip()
        if actual_name != self.EXPECTED_SERVER_NAME:
            self._initialized = False
            raise RuntimeError(
                f"mcp_server_identity_mismatch:vm-edge:expected={self.EXPECTED_SERVER_NAME}:actual={actual_name or 'missing'}"
            )
        self._identity_validated = True
        return init_result

    async def _invoke(self, name: str, target: str, **params: Any) -> Dict[str, Any]:
        if self._backend == "agent" and not self._endpoint_direct:
            # No target supplied by an alarm, chatbot or LLM can select its own
            # URL. Only this operator-managed target-to-endpoint map can route.
            endpoint = settings.VM_AGENT_ENDPOINTS.get(target)
            if not endpoint:
                raise PermissionError("vm_target_not_allowed")
            worker = VMEdgeMCPClient(server_url=endpoint)
            try:
                return await worker._invoke(name, target, **params)
            finally:
                await worker.close()
        result = await self.call_tool(name, {"target": target, **params})
        if isinstance(result.get("content"), list) and result["content"]:
            first = result["content"][0]
            if isinstance(first, dict):
                return first
        return result

    async def collect_vm_metrics(self, target: str) -> Dict[str, Any]: return await self._invoke("collect_vm_metrics", target)
    async def collect_metrics(self, target: str) -> Dict[str, Any]: return await self.collect_vm_metrics(target)
    async def memory_diagnostics(self, target: str) -> Dict[str, Any]: return await self._invoke("memory_diagnostics", target)
    async def host_info(self, target: str) -> Dict[str, Any]: return await self._invoke("host_info", target)
    async def disk_status(self, target: str) -> Dict[str, Any]: return await self._invoke("disk_status", target)
    async def disk_forensics(self, target: str) -> Dict[str, Any]: return await self._invoke("disk_forensics", target)
    async def network_status(self, target: str) -> Dict[str, Any]: return await self._invoke("network_status", target)
    async def service_status(self, target: str, service: str) -> Dict[str, Any]: return await self._invoke("service_status", target, service=service)
    async def service_logs(self, target: str, service: str, limit: int = 150) -> Dict[str, Any]: return await self._invoke("service_logs", target, service=service, limit=limit)
    async def system_logs(self, target: str, limit: int = 50) -> Dict[str, Any]: return await self._invoke("system_logs", target, limit=limit)
    async def process_snapshot(self, target: str) -> Dict[str, Any]: return await self._invoke("process_snapshot", target)
    async def process_status(self, target: str, process: str) -> Dict[str, Any]: return await self._invoke("process_status", target, process=process)
    async def tcp_check(self, target: str, host: str, port: int) -> Dict[str, Any]: return await self._invoke("tcp_check", target, host=host, port=port)
    async def port_listener_status(self, target: str, port: int) -> Dict[str, Any]: return await self._invoke("port_listener_status", target, port=port)
    async def dns_check(self, target: str, hostname: str) -> Dict[str, Any]: return await self._invoke("dns_check", target, hostname=hostname)
    async def route_check(self, target: str, destination: str) -> Dict[str, Any]: return await self._invoke("route_check", target, destination=destination)
    async def firewall_status(self, target: str) -> Dict[str, Any]: return await self._invoke("firewall_status", target)
    async def config_validate(self, target: str, service: str) -> Dict[str, Any]: return await self._invoke("config_validate", target, service=service)
    async def nginx_config_review(self, target: str, service: str) -> Dict[str, Any]: return await self._invoke("nginx_config_review", target, service=service)
    async def nginx_config_inspect(self, target: str, service: str) -> Dict[str, Any]: return await self._invoke("nginx_config_inspect", target, service=service)
    async def service_runtime_discovery(self, target: str, service: str) -> Dict[str, Any]: return await self._invoke("service_runtime_discovery", target, service=service)
    async def service_config_discovery(self, target: str, service: str) -> Dict[str, Any]: return await self._invoke("service_config_discovery", target, service=service)
    async def service_config_review(self, target: str, service: str) -> Dict[str, Any]: return await self._invoke("service_config_review", target, service=service)
    async def service_config_llm_repair(self, target: str, service: str) -> Dict[str, Any]: return await self._invoke("service_config_llm_repair", target, service=service)
    async def dotnet_config_syntax(self, target: str, service: str) -> Dict[str, Any]: return await self._invoke("dotnet_config_syntax", target, service=service)

    async def config_change_validate(self, target: str, **parameters: Any) -> Dict[str, Any]:
        return await self._invoke("config_change_validate", target, **parameters)

    async def config_change_apply(self, target: str, *, service: str, claims: dict,
                                  signature: str) -> Dict[str, Any]:
        return await self._invoke(
            "config_change_apply", target, service=service, claims=claims, signature=signature,
        )

    @staticmethod
    def _write_context(approval_id: str, incident_id: str) -> Dict[str, str]:
        if not approval_id:
            raise PermissionError("mcp_write_approval_id_required")
        if not incident_id:
            raise PermissionError("mcp_write_incident_id_required")
        return {"approval_id": approval_id, "incident_id": incident_id}

    async def restart_service(self, target: str, service: str, approval_id: str, incident_id: str) -> Dict[str, Any]:
        return await self._invoke("restart_service", target, service=service, **self._write_context(approval_id, incident_id))

    async def reload_service(self, target: str, service: str, approval_id: str, incident_id: str) -> Dict[str, Any]:
        return await self._invoke("reload_service", target, service=service, **self._write_context(approval_id, incident_id))

    async def start_service(self, target: str, service: str, approval_id: str, incident_id: str) -> Dict[str, Any]:
        return await self._invoke("start_service", target, service=service, **self._write_context(approval_id, incident_id))
