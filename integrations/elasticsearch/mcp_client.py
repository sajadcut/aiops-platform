from __future__ import annotations

from datetime import datetime, timezone
from typing import List, Optional

from domain.contracts.config import settings
from integrations.base import LogEntry
from integrations.mcp_client import MCPClient


class ElasticsearchMCPClient(MCPClient):
    """Canonical Control-Plane connector for Elastic log Evidence via MCP."""

    def __init__(self, server_url: Optional[str] = None):
        super().__init__(
            server_url or settings.ELASTICSEARCH_MCP_URL,
            "elasticsearch",
            allowed_tools={"search_logs"},
            protocol_version=settings.MCP_PROTOCOL_VERSION,
            timeout=settings.MCP_TIMEOUT_SECONDS,
            bearer_token=settings.MCP_BEARER_TOKEN,
            ca_cert_path=settings.MCP_CA_CERT_PATH,
            client_cert_path=settings.MCP_CLIENT_CERT_PATH,
            client_key_path=settings.MCP_CLIENT_KEY_PATH,
            require_https=settings.MCP_REQUIRE_HTTPS,
        )

    async def get_logs(
        self,
        service: str,
        since: datetime,
        until: Optional[datetime] = None,
        level: Optional[str] = None,
        limit: int = 100,
    ) -> List[LogEntry]:
        result = await self.call_tool("search_logs", {
            "service": service,
            "since": since.isoformat(),
            "until": until.isoformat() if until else None,
            "level": level,
            "limit": min(max(int(limit), 1), 500),
        })
        logs: List[LogEntry] = []
        for item in result.get("content", []):
            raw_ts = item.get("@timestamp") or item.get("timestamp")
            try:
                timestamp = datetime.fromisoformat(str(raw_ts).replace("Z", "+00:00")) if raw_ts else datetime.now(timezone.utc)
            except ValueError:
                timestamp = datetime.now(timezone.utc)
            service_value = item.get("service")
            if isinstance(service_value, dict):
                service_value = service_value.get("name")
            logs.append(LogEntry(
                timestamp=timestamp,
                service=str(service_value or item.get("service.name") or service),
                level=str(item.get("level") or (item.get("log") or {}).get("level") or "info"),
                message=str(item.get("message") or ""),
                source="elasticsearch",
                raw_data=item,
            ))
        return logs
