from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, List, Optional
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from domain.contracts.config import settings
from integrations.base import LogEntry
from integrations.mcp_client import MCPClient


class ElasticsearchMCPClient(MCPClient):
    """Canonical Elastic Agent Builder MCP adapter for Elastic Stack >= 9.2.

    The deprecated standalone ``elastic/mcp-server-elasticsearch`` contract is
    intentionally unsupported. The Control Plane connects to Kibana Agent
    Builder MCP and uses only the deterministic, read-only
    ``platform.core.execute_esql`` capability for log Evidence collection.
    """

    TOOL_EXECUTE_ESQL = "platform.core.execute_esql"

    def __init__(self, server_url: Optional[str] = None):
        base_url = server_url or settings.ELASTICSEARCH_MCP_URL
        super().__init__(
            self._with_namespace(base_url, settings.ELASTIC_AGENT_BUILDER_MCP_NAMESPACES),
            "elastic-agent-builder",
            allowed_tools={self.TOOL_EXECUTE_ESQL},
            protocol_version=settings.MCP_PROTOCOL_VERSION,
            timeout=settings.MCP_TIMEOUT_SECONDS,
            bearer_token=settings.MCP_BEARER_TOKEN,
            authorization_header=settings.ELASTICSEARCH_MCP_AUTH_HEADER,
            ca_cert_path=settings.MCP_CA_CERT_PATH,
            client_cert_path=settings.MCP_CLIENT_CERT_PATH,
            client_key_path=settings.MCP_CLIENT_KEY_PATH,
            require_https=settings.MCP_REQUIRE_HTTPS,
        )

    @staticmethod
    def _with_namespace(url: str, namespaces: List[str]) -> str:
        values = [str(value).strip() for value in namespaces if str(value).strip()]
        if not values:
            return url
        parts = urlsplit(url)
        query = dict(parse_qsl(parts.query, keep_blank_values=True))
        query["namespace"] = ",".join(values)
        return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(query), parts.fragment))

    @staticmethod
    def _esql_string(value: str) -> str:
        # ES|QL string literals use double quotes. Escaping is deterministic and
        # owned by the adapter; Agent/LLM input never becomes an executable query.
        return '"' + str(value).replace("\\", "\\\\").replace('"', '\\"') + '"'

    @staticmethod
    def _rows_from_payload(payload: Any) -> list[dict[str, Any]]:
        """Normalize Agent Builder execute_esql output into row dictionaries."""
        if not isinstance(payload, dict):
            return []
        if isinstance(payload.get("rows"), list):
            return [row for row in payload["rows"] if isinstance(row, dict)]

        # Tools API/MCP output can contain typed result entries. Locate a data
        # block with columns + values and convert its tabular response to rows.
        results = payload.get("results")
        if isinstance(results, list):
            rows: list[dict[str, Any]] = []
            for result in results:
                if not isinstance(result, dict):
                    continue
                data = result.get("data")
                if not isinstance(data, dict):
                    continue
                columns = data.get("columns")
                values = data.get("values") or data.get("rows")
                if not isinstance(columns, list) or not isinstance(values, list):
                    continue
                names = [str(col.get("name")) if isinstance(col, dict) else str(col) for col in columns]
                for value_row in values:
                    if isinstance(value_row, list):
                        rows.append({name: value_row[index] if index < len(value_row) else None for index, name in enumerate(names)})
                    elif isinstance(value_row, dict):
                        rows.append(value_row)
            return rows

        columns = payload.get("columns")
        values = payload.get("values")
        if isinstance(columns, list) and isinstance(values, list):
            names = [str(col.get("name")) if isinstance(col, dict) else str(col) for col in columns]
            return [
                {name: row[index] if index < len(row) else None for index, name in enumerate(names)}
                for row in values
                if isinstance(row, list)
            ]
        return []

    async def get_logs(
        self,
        service: str,
        since: datetime,
        until: Optional[datetime] = None,
        level: Optional[str] = None,
        limit: int = 100,
    ) -> List[LogEntry]:
        bounded_limit = min(max(int(limit), 1), 500)
        end = until or datetime.now(timezone.utc)
        service_literal = self._esql_string(service)
        clauses = [
            f"@timestamp >= TO_DATETIME({self._esql_string(since.astimezone(timezone.utc).isoformat())})",
            f"@timestamp <= TO_DATETIME({self._esql_string(end.astimezone(timezone.utc).isoformat())})",
            f"(service.name == {service_literal} OR service == {service_literal})",
        ]
        if level:
            level_literal = self._esql_string(level)
            clauses.append(f"(log.level == {level_literal} OR level == {level_literal})")

        index_pattern = settings.ELASTIC_AGENT_BUILDER_INDEX_PATTERN.strip()
        query = (
            f"FROM {index_pattern} | WHERE "
            + " AND ".join(clauses)
            + " | SORT @timestamp DESC"
            + " | KEEP @timestamp, message, service.name, service, log.level, level, host.name, trace.id, transaction.id"
            + f" | LIMIT {bounded_limit}"
        )

        result = await self.call_tool(self.TOOL_EXECUTE_ESQL, {"query": query})
        rows: list[dict[str, Any]] = []
        for payload in self.json_content(result):
            rows.extend(self._rows_from_payload(payload))

        logs: List[LogEntry] = []
        for item in rows:
            raw_ts = item.get("@timestamp") or item.get("timestamp")
            try:
                timestamp = datetime.fromisoformat(str(raw_ts).replace("Z", "+00:00")) if raw_ts else datetime.now(timezone.utc)
            except (ValueError, TypeError):
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
