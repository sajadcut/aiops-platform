from __future__ import annotations

from datetime import datetime, timezone
from typing import List, Optional

from domain.contracts.config import settings
from integrations.base import Alert, MetricPoint
from integrations.mcp_client import MCPClient


class PrometheusMCPClient(MCPClient):
    """Canonical Control-Plane connector for Prometheus/Alertmanager via MCP."""

    def __init__(self, server_url: Optional[str] = None):
        super().__init__(
            server_url or settings.PROMETHEUS_MCP_URL,
            "prometheus",
            allowed_tools={"query_metrics", "get_prometheus_alerts"},
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
        try:
            return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        except ValueError:
            return datetime.now(timezone.utc)

    async def get_metrics(self, service: str, metric_names: List[str], since: datetime, until: Optional[datetime] = None) -> List[MetricPoint]:
        result = await self.call_tool("query_metrics", {
            "service": service,
            "metric_names": [str(x) for x in metric_names[:25]],
            "since": since.isoformat(),
            "until": until.isoformat() if until else None,
        })
        return [MetricPoint(
            timestamp=self._dt(item.get("timestamp")),
            service=str(item.get("service") or service),
            name=str(item.get("metric_name") or item.get("name") or "unknown"),
            value=float(item.get("value", 0.0)),
            labels=item.get("labels", {}) or {},
            source="prometheus",
        ) for item in result.get("content", [])]

    async def get_alerts(self, since: Optional[datetime] = None, service: Optional[str] = None, limit: int = 100) -> List[Alert]:
        result = await self.call_tool("get_prometheus_alerts", {
            "service": service,
            "limit": min(max(int(limit), 1), 500),
            "since": since.isoformat() if since else None,
        })
        return [Alert(
            source="prometheus",
            source_id=str(item.get("fingerprint") or item.get("id") or ""),
            severity=str(item.get("severity") or "unknown"),
            service=str(item.get("service") or service or "unknown"),
            message=str(item.get("message") or item.get("summary") or ""),
            timestamp=self._dt(item.get("activeAt") or item.get("timestamp")),
            raw_data=item,
        ) for item in result.get("content", [])]
