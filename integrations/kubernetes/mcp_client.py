from __future__ import annotations

from typing import Any, Dict, List, Optional

from domain.contracts.config import settings
from integrations.mcp_client import MCPClient


class KubernetesMCPClient(MCPClient):
    """Read-only Kubernetes Evidence connector through MCP."""

    def __init__(self, server_url: Optional[str] = None):
        url = server_url or settings.KUBERNETES_MCP_URL
        if not url:
            raise ValueError("kubernetes_mcp_url_not_configured")
        super().__init__(
            url,
            "kubernetes",
            allowed_tools={"collect_kubernetes_evidence"},
            protocol_version=settings.MCP_PROTOCOL_VERSION,
            timeout=settings.MCP_TIMEOUT_SECONDS,
            bearer_token=settings.MCP_BEARER_TOKEN,
            ca_cert_path=settings.MCP_CA_CERT_PATH,
            client_cert_path=settings.MCP_CLIENT_CERT_PATH,
            client_key_path=settings.MCP_CLIENT_KEY_PATH,
            require_https=settings.MCP_REQUIRE_HTTPS,
        )
        self.enabled = True

    async def collect_evidence(self, service: str) -> List[Dict[str, Any]]:
        result = await self.call_tool("collect_kubernetes_evidence", {"service": service})
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
