from app.integrations.mcp_client import MCPClient
from app.integrations.base import MetricPoint, Alert
from datetime import datetime
from typing import Optional, List

class PrometheusMCPClient(MCPClient):
    def __init__(self, server_url: str = "http://prometheus-mcp:9090"):
        super().__init__(server_url, "prometheus")

    async def get_metrics(
        self,
        service: str,
        metric_names: List[str],
        since: datetime,
        until: Optional[datetime] = None
    ) -> List[MetricPoint]:
        """دریافت متریک‌ها از Prometheus از طریق MCP"""
        args = {
            "service": service,
            "metric_names": metric_names,
            "since": since.isoformat(),
            "until": until.isoformat() if until else None
        }
        result = await self._call_tool("query_metrics", args)
        
        metrics = []
        for item in result.get("content", []):
            metrics.append(MetricPoint(
                timestamp=datetime.fromisoformat(item.get("timestamp")),
                service=service,
                name=item.get("metric_name"),
                value=float(item.get("value", 0.0)),
                labels=item.get("labels", {}),
                source="prometheus"
            ))
        return metrics

    async def get_alerts(
        self, since: Optional[datetime] = None, service: Optional[str] = None, limit: int = 100
    ) -> List[Alert]:
        """دریافت Alertها از AlertManager از طریق MCP"""
        args = {
            "service": service,
            "limit": limit,
            "since": since.isoformat() if since else None
        }
        result = await self._call_tool("get_prometheus_alerts", args)
        
        alerts = []
        for item in result.get("content", []):
            alerts.append(Alert(
                source="prometheus",
                source_id=item.get("fingerprint"),
                severity=item.get("severity", "unknown"),
                service=service,
                message=item.get("message", ""),
                timestamp=datetime.fromisoformat(item.get("activeAt")),
                raw_data=item
            ))
        return alerts