# app/integrations/zabbix/mcp_client.py
from app.integrations.mcp_client import MCPClient
from app.integrations.base import Alert, LogEntry, MetricPoint
from datetime import datetime
from typing import Optional, List

class ZabbixMCPClient(MCPClient):
    def __init__(self, server_url: str = "http://zabbix-mcp:9000"):
        super().__init__(server_url, "zabbix")

    async def get_alerts(
        self, 
        since: Optional[datetime] = None, 
        service: Optional[str] = None, 
        limit: int = 100
    ) -> List[Alert]:
        """دریافت Alertها از Zabbix از طریق MCP"""
        arguments = {
            "service": service,
            "limit": limit,
            "since": since.isoformat() if since else None
        }
        result = await self._call_tool("get_zabbix_alerts", arguments)
        
        alerts = []
        for item in result.get("content", []):
            alerts.append(Alert(
                source="zabbix",
                source_id=item.get("eventid"),
                severity=item.get("severity", "unknown"),
                service=service,
                message=item.get("name", ""),
                timestamp=datetime.fromisoformat(item.get("clock")),
                raw_data=item
            ))
        return alerts

    # متدهای دیگر مثل get_logs و get_metrics در صورت نیاز