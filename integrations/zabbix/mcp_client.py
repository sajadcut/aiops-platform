from __future__ import annotations

from datetime import datetime, timezone
from typing import List, Optional

from domain.contracts.config import settings
from integrations.base import Alert
from integrations.mcp_client import MCPClient


class ZabbixMCPClient(MCPClient):
    """Canonical Control-Plane connector for Zabbix alert Evidence via MCP."""

    def __init__(self, server_url: Optional[str] = None):
        super().__init__(
            server_url or settings.ZABBIX_MCP_URL,
            "zabbix",
            allowed_tools={"get_zabbix_alerts"},
            protocol_version=settings.MCP_PROTOCOL_VERSION,
            timeout=settings.MCP_TIMEOUT_SECONDS,
            bearer_token=settings.MCP_BEARER_TOKEN,
            ca_cert_path=settings.MCP_CA_CERT_PATH,
            client_cert_path=settings.MCP_CLIENT_CERT_PATH,
            client_key_path=settings.MCP_CLIENT_KEY_PATH,
            require_https=settings.MCP_REQUIRE_HTTPS,
        )

    @staticmethod
    def _dt(value: object) -> datetime:
        if not value:
            return datetime.now(timezone.utc)
        text = str(value)
        if text.isdigit():
            return datetime.fromtimestamp(int(text), tz=timezone.utc)
        try:
            return datetime.fromisoformat(text.replace("Z", "+00:00"))
        except ValueError:
            return datetime.now(timezone.utc)

    async def get_alerts(self, since: Optional[datetime] = None, service: Optional[str] = None, limit: int = 100) -> List[Alert]:
        result = await self.call_tool("get_zabbix_alerts", {
            "service": service,
            "limit": min(max(int(limit), 1), 500),
            "since": since.isoformat() if since else None,
        })
        alerts: List[Alert] = []
        for item in result.get("content", []):
            alerts.append(Alert(
                source="zabbix",
                source_id=str(item.get("eventid") or item.get("id") or ""),
                severity=str(item.get("severity") or "unknown"),
                service=str(item.get("service") or service or "unknown"),
                message=str(item.get("name") or item.get("message") or ""),
                timestamp=self._dt(item.get("clock") or item.get("timestamp")),
                raw_data=item,
            ))
        return alerts
