from __future__ import annotations

from typing import Any, Dict, List, Optional

from domain.contracts.config import settings
from integrations.mcp_client import MCPClient


class KubernetesMCPClient(MCPClient):
    """Kubernetes evidence + explicitly governed write connector through MCP.

    Read evidence uses the normal MCP identity. Mutating tools use the separate
    write identity and are never retried by MCPClient. The remote Kubernetes MCP
    must independently validate the signed execution capability it receives.
    """

    READ_TOOL = "collect_kubernetes_evidence"
    WRITE_TOOLS = {
        "restart_kubernetes_workload",
        "rollback_kubernetes_workload",
        "scale_kubernetes_workload",
    }

    def __init__(self, server_url: Optional[str] = None):
        url = server_url or settings.KUBERNETES_MCP_URL
        if not url:
            raise ValueError("kubernetes_mcp_url_not_configured")
        super().__init__(
            url,
            "kubernetes",
            allowed_tools={self.READ_TOOL, *self.WRITE_TOOLS},
            write_tools=self.WRITE_TOOLS,
            protocol_version=settings.MCP_PROTOCOL_VERSION,
            timeout=settings.MCP_TIMEOUT_SECONDS,
            bearer_token=settings.MCP_BEARER_TOKEN,
            write_bearer_token=settings.MCP_WRITE_BEARER_TOKEN,
            ca_cert_path=settings.MCP_CA_CERT_PATH,
            client_cert_path=settings.MCP_CLIENT_CERT_PATH,
            client_key_path=settings.MCP_CLIENT_KEY_PATH,
            require_https=settings.MCP_REQUIRE_HTTPS,
        )
        self.enabled = True

    async def collect_evidence(self, service: str) -> List[Dict[str, Any]]:
        result = await self.call_tool(self.READ_TOOL, {"service": service})
        rows = result.get("content", [])
        evidence: List[Dict[str, Any]] = []
        for item in rows:
            if not isinstance(item, dict):
                continue
            evidence.append({
                "type": str(item.get("type") or "event"),
                "source": "kubernetes_api",
                "reference": item.get("reference") or item.get("uid"),
                "timestamp": item.get("timestamp"),
                "raw_data": item.get("raw_data") if isinstance(item.get("raw_data"), dict) else item,
            })
        return evidence

    @staticmethod
    def _write_args(
        *, target: str, namespace: str, approval_id: str, incident_id: str,
        execution_capability: str, extra: Dict[str, Any] | None = None,
    ) -> Dict[str, Any]:
        if not all((target, namespace, approval_id, incident_id, execution_capability)):
            raise ValueError("kubernetes_write_binding_incomplete")
        return {
            "target": target,
            "namespace": namespace,
            "approval_id": approval_id,
            "incident_id": incident_id,
            "execution_capability": execution_capability,
            **(extra or {}),
        }

    async def restart_workload(
        self, target: str, namespace: str, approval_id: str,
        incident_id: str, execution_capability: str,
    ) -> Dict[str, Any]:
        return await self.call_tool(
            "restart_kubernetes_workload",
            self._write_args(
                target=target, namespace=namespace, approval_id=approval_id,
                incident_id=incident_id, execution_capability=execution_capability,
            ),
        )

    async def rollback_workload(
        self, target: str, namespace: str, approval_id: str, incident_id: str,
        execution_capability: str, revision: str | None = None,
    ) -> Dict[str, Any]:
        return await self.call_tool(
            "rollback_kubernetes_workload",
            self._write_args(
                target=target, namespace=namespace, approval_id=approval_id,
                incident_id=incident_id, execution_capability=execution_capability,
                extra={"revision": revision} if revision else {},
            ),
        )

    async def scale_workload(
        self, target: str, namespace: str, replicas: int, approval_id: str,
        incident_id: str, execution_capability: str,
    ) -> Dict[str, Any]:
        if replicas < 0 or replicas > 100:
            raise ValueError("kubernetes_scale_replicas_out_of_bounds")
        return await self.call_tool(
            "scale_kubernetes_workload",
            self._write_args(
                target=target, namespace=namespace, approval_id=approval_id,
                incident_id=incident_id, execution_capability=execution_capability,
                extra={"replicas": replicas},
            ),
        )
