from __future__ import annotations

import base64
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
    ``platform_core_execute_esql`` wire tool (logical ``platform.core.execute_esql``)
    for log Evidence collection.
    """

    # Kibana Agent Builder exposes namespace separators as underscores in tools/list.
    # Permit the exact MCP wire name, not the dotted logical identifier.
    TOOL_EXECUTE_ESQL = "platform_core_execute_esql"

    def __init__(self, server_url: Optional[str] = None):
        base_url = server_url or settings.ELASTICSEARCH_MCP_URL
        super().__init__(
            self._with_namespace(base_url, settings.ELASTIC_AGENT_BUILDER_MCP_NAMESPACES),
            "elastic-agent-builder",
            allowed_tools={self.TOOL_EXECUTE_ESQL},
            protocol_version=settings.ELASTICSEARCH_MCP_PROTOCOL_VERSION,
            timeout=settings.MCP_TIMEOUT_SECONDS,
            # Elastic Agent Builder has its own provider credential. Never leak
            # the generic/internal MCP bearer token to Kibana.
            bearer_token=None,
            authorization_header=self._configured_authorization_header(),
            client_cert_path=settings.MCP_CLIENT_CERT_PATH,
            client_key_path=settings.MCP_CLIENT_KEY_PATH,
        )

    @staticmethod
    def _configured_authorization_header() -> Optional[str]:
        """Resolve Elastic MCP auth without exposing raw Basic credentials to the generic client."""
        explicit = str(settings.ELASTICSEARCH_MCP_AUTH_HEADER or "").strip()
        if explicit:
            return explicit

        username = str(settings.ELASTICSEARCH_MCP_USERNAME or "").strip()
        password = settings.ELASTICSEARCH_MCP_PASSWORD
        if username and password is not None and password != "":
            encoded = base64.b64encode(f"{username}:{password}".encode("utf-8")).decode("ascii")
            return f"Basic {encoded}"
        return None

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

    async def health_check(self) -> bool:
        """Require the exact allowlisted Agent Builder tool, not just a live MCP route."""
        try:
            tools = await self.list_tools()
            return any(tool.get("name") == self.TOOL_EXECUTE_ESQL for tool in tools)
        except Exception:
            return False

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
        # Operator-configured aliases only; never infer GFP_Backend == gfpapi.
        aliases = getattr(settings, "ELASTIC_SERVICE_DISCOVERY_ALIASES", {}) or {}
        values = aliases.get(service, []) if isinstance(aliases, dict) else []
        names = [service]
        if isinstance(values, list):
            for alias in values[:4]:
                if isinstance(alias, str) and alias.strip() and alias.strip() not in names:
                    names.append(alias.strip())
        lower = self._esql_string(since.astimezone(timezone.utc).isoformat())
        upper = self._esql_string(end.astimezone(timezone.utc).isoformat())
        fields = ("service.name", "service", "Properties.ServiceName.keyword",
                  "Properties.ServiceName", "service.name.keyword")
        index_pattern = settings.ELASTIC_AGENT_BUILDER_INDEX_PATTERN.strip()
        rows: list[dict[str, Any]] = []
        succeeded = 0
        last_error: Exception | None = None
        for name in names:
            for field in fields:
                clauses = [
                    f"@timestamp >= TO_DATETIME({lower})",
                    f"@timestamp <= TO_DATETIME({upper})",
                    f"`{field}` == {self._esql_string(name)}",
                ]
                if level:
                    clauses.append(f"`log.level` == {self._esql_string(level)}")
                query = (
                    f"FROM {index_pattern} | WHERE " + " AND ".join(clauses)
                    + " | SORT @timestamp DESC"
                    + " | KEEP @timestamp, message, host.name, host.ip, service.name,"
                    + " service, Properties.ServiceName.keyword, Properties.ServiceName, log.level, level"
                    + f" | LIMIT {bounded_limit}"
                )
                try:
                    result = await self.call_tool(self.TOOL_EXECUTE_ESQL, {"query": query})
                    succeeded += 1
                except Exception as exc:
                    last_error = exc
                    continue
                for payload in self.json_content(result):
                    rows.extend(self._rows_from_payload(payload))
                if rows:
                    break
            if rows:
                break
        if not succeeded and last_error is not None:
            raise RuntimeError("elastic_all_service_field_queries_failed") from last_error

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
                service=str(service_value or item.get("service.name") or item.get("Properties.ServiceName.keyword") or item.get("Properties.ServiceName") or service),
                level=str(item.get("level") or (item.get("log") or {}).get("level") or "info"),
                message=str(item.get("message") or ""),
                source="elasticsearch",
                raw_data=item,
            ))
        return logs

    async def discover_service_hosts(
        self, service: str, since: datetime, until: Optional[datetime] = None,
    ) -> dict[str, Any]:
        """Bounded, read-only Elasticsearch host *candidates*, never VM authority."""
        if not str(service or "").strip():
            return {"status": "service_unknown", "candidates": [], "result_count": 0}
        logs = await self.get_logs(service, since, until, limit=40)
        hosts: dict[str, dict[str, Any]] = {}
        for log in logs:
            raw = log.raw_data if isinstance(log.raw_data, dict) else {}
            host = raw.get("host")
            if not isinstance(host, dict):
                host = {}
            hostname = str(raw.get("host.name") or host.get("name") or "").strip()
            if not hostname or len(hostname) > 253:
                continue
            ips = raw.get("host.ip") or host.get("ip") or []
            if isinstance(ips, str):
                ips = [ips]
            ips = [str(ip) for ip in ips[:6]] if isinstance(ips, list) else []
            candidate = hosts.setdefault(hostname, {
                "hostname": hostname, "ip_addresses": ips,
                "source": "elasticsearch", "status": "candidate", "record_count": 0,
            })
            candidate["record_count"] += 1
        return {
            "status": "candidates_found" if hosts else "no_host_metadata",
            "searched_service": service, "result_count": len(logs),
            "candidates": list(hosts.values())[:8],
            "requires_independent_verification": True,
        }
