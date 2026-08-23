from integrations.mcp_client import MCPClient
from integrations.base import LogEntry
from datetime import datetime
from typing import Optional, List

class ElasticsearchMCPClient(MCPClient):
    def __init__(self, server_url: str = "http://elasticsearch-mcp:9200"):
        super().__init__(server_url, "elasticsearch")

    async def get_logs(
        self, service: str, since: datetime, until: Optional[datetime] = None,
        level: Optional[str] = None, limit: int = 100
    ) -> List[LogEntry]:
        args = {
            "service": service,
            "since": since.isoformat(),
            "until": until.isoformat() if until else None,
            "level": level,
            "limit": limit
        }
        result = await self._call_tool("search_logs", args)
        logs = []
        for item in result.get("content", []):
            logs.append(LogEntry(
                timestamp=datetime.fromisoformat(item.get("@timestamp")),
                service=service,
                level=item.get("level", "info"),
                message=item.get("message", ""),
                source="elasticsearch",
                raw_data=item
            ))
        return logs