from __future__ import annotations

from datetime import datetime, timezone
from typing import List, Optional

from domain.contracts.config import settings
from integrations.base import LogEntry
from integrations.mcp_client import MCPClient


class ElasticsearchMCPClient(MCPClient):
    """Elastic upstream MCP adapter using list_indices/search/esql contracts."""

    def __init__(self, server_url: Optional[str] = None):
        super().__init__(
            server_url or settings.ELASTICSEARCH_MCP_URL,
            "elasticsearch",
            allowed_tools={"list_indices", "get_mappings", "search", "esql", "get_shards"},
            protocol_version=settings.MCP_PROTOCOL_VERSION,
            timeout=settings.MCP_TIMEOUT_SECONDS,
            bearer_token=settings.MCP_BEARER_TOKEN,
            authorization_header=settings.ELASTICSEARCH_MCP_AUTH_HEADER,
            ca_cert_path=settings.MCP_CA_CERT_PATH,
            client_cert_path=settings.MCP_CLIENT_CERT_PATH,
            client_key_path=settings.MCP_CLIENT_KEY_PATH,
            require_https=settings.MCP_REQUIRE_HTTPS,
        )

    async def get_logs(self, service: str, since: datetime, until: Optional[datetime] = None, level: Optional[str] = None, limit: int = 100) -> List[LogEntry]:
        filters = [
            {"range": {"@timestamp": {"gte": since.isoformat(), **({"lte": until.isoformat()} if until else {})}}},
            {"bool": {"should": [
                {"term": {"service.name": service}},
                {"term": {"service": service}},
                {"match_phrase": {"service.name": service}},
            ], "minimum_should_match": 1}},
        ]
        if level:
            filters.append({"bool": {"should": [
                {"term": {"log.level": level}},
                {"term": {"level": level}},
            ], "minimum_should_match": 1}})
        query_body = {
            "size": min(max(int(limit), 1), 500),
            "sort": [{"@timestamp": {"order": "desc"}}],
            "query": {"bool": {"filter": filters}},
        }
        result = await self.call_tool("search", {
            "index": settings.ELASTICSEARCH_MCP_INDEX_PATTERN,
            "fields": ["@timestamp", "message", "service.name", "service", "log.level", "level", "host.name", "trace.id", "transaction.id"],
            "query_body": query_body,
        })
        logs: List[LogEntry] = []
        for item in self.json_content(result):
            if not isinstance(item, dict):
                continue
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
