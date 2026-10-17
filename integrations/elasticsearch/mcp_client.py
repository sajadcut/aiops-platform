from __future__ import annotations

import base64
from datetime import datetime, timezone
from typing import Any, List, Optional
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from domain.contracts.config import settings
from domain.contracts.logging import logger
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
        """Normalize bounded Agent Builder ES|QL result envelopes.

        Kibana/MCP versions may nest ES|QL tabular data under result/data,
        structuredContent/results or return column/value pairs. Never interpret
        string contents as instructions or log their contents.
        """
        def decode(value: Any, depth: int) -> list[dict[str, Any]]:
            if depth > 5 or not isinstance(value, dict):
                return []
            columns = value.get("columns")
            data_rows = value.get("values")
            if data_rows is None:
                data_rows = value.get("rows")
            if isinstance(columns, list) and isinstance(data_rows, list):
                names = [str(col.get("name") or "") if isinstance(col, dict) else str(col)
                         for col in columns]
                return [
                    ({name: row[i] if i < len(row) else None for i, name in enumerate(names)}
                     if isinstance(row, list) else row)
                    for row in data_rows[:500] if isinstance(row, (list, dict))
                ]
            rows = value.get("rows")
            if isinstance(rows, list) and all(isinstance(row, dict) for row in rows):
                return rows[:500]
            for key in ("result", "data", "structuredContent", "results"):
                nested = value.get(key)
                if isinstance(nested, dict):
                    decoded = decode(nested, depth + 1)
                    if decoded:
                        return decoded
                elif isinstance(nested, list):
                    decoded: list[dict[str, Any]] = []
                    for child in nested[:10]:
                        decoded.extend(decode(child, depth + 1))
                        if len(decoded) >= 500:
                            break
                    if decoded:
                        return decoded[:500]
            return []
        return decode(payload, 0)

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
        unrecognized_payloads = 0
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
                # ES|QL fails if a projected field is unmapped. Degrade
                # projection independently of the service lookup field.
                projections = (
                    f"@timestamp, message, `host.name`, `host.ip`, `{field}`",
                    f"@timestamp, `host.name`, `host.ip`, `{field}`",
                    f"@timestamp, `host.name`, `{field}`",
                    f"@timestamp, `host.ip`, `{field}`",
                    f"@timestamp, message, `{field}`",
                    f"@timestamp, `{field}`",
                )
                result = None
                for projection in projections:
                    query = (
                        f"FROM {index_pattern} | WHERE " + " AND ".join(clauses)
                        + " | SORT @timestamp DESC | KEEP " + projection
                        + f" | LIMIT {bounded_limit}"
                    )
                    try:
                        result = await self.call_tool(self.TOOL_EXECUTE_ESQL, {"query": query})
                        succeeded += 1
                        break
                    except Exception as exc:
                        last_error = exc
                if result is None:
                    continue
                payloads = self.json_content(result)
                for payload in payloads:
                    decoded = self._rows_from_payload(payload)
                    if not decoded and isinstance(payload, dict) and not (
                        payload.get("rows") == [] or payload.get("values") == []
                    ):
                        unrecognized_payloads += 1
                    rows.extend(decoded)
                if rows:
                    break
            if rows:
                break
        logger.info(
            "elastic_service_query_summary",
            service=str(service)[:90],
            index_pattern=index_pattern[:160],
            searched_name_count=len(names),
            searched_field_count=len(fields),
            successful_queries=succeeded,
            decoded_rows=len(rows),
            unrecognized_envelopes=unrecognized_payloads,
        )
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
        import ipaddress
        for log in logs:
            raw = log.raw_data if isinstance(log.raw_data, dict) else {}
            host = raw.get("host")
            if not isinstance(host, dict):
                host = {}
            hostname = str(raw.get("host.name") or host.get("name") or "").strip()
            raw_ips = raw.get("host.ip") or host.get("ip") or []
            if isinstance(raw_ips, str):
                raw_ips = [raw_ips]
            ips: list[str] = []
            if isinstance(raw_ips, list):
                for value in raw_ips[:6]:
                    try:
                        ip = ipaddress.ip_address(str(value).strip())
                        if not (ip.is_loopback or ip.is_unspecified or ip.is_multicast):
                            ips.append(str(ip))
                    except ValueError:
                        continue
            if len(hostname) > 253:
                hostname = ""
            # Explicit IP-only ECS logs are useful discovery candidates too;
            # never derive a host from a message, LLM or an index-wide probe.
            key = hostname or (ips[0] if ips else "")
            if not key:
                continue
            candidate = hosts.setdefault(key.casefold(), {
                "hostname": key, "ip_addresses": [],
                "source": "elasticsearch", "status": "candidate",
                "record_count": 0,
            })
            for ip in ips:
                if ip not in candidate["ip_addresses"]:
                    candidate["ip_addresses"].append(ip)
            candidate["record_count"] += 1
        # A transport-level HTTP 200 doesn't prove a service/time match.
        # Probe one document from the operator-configured index (without
        # exposing its contents) to separate empty index from mismatched
        # filters. Index-only samples NEVER produce host candidates.
        index_probe = "not_needed"
        indexed_fields: list[str] = []
        if not logs:
            try:
                probe = await self.call_tool(
                    self.TOOL_EXECUTE_ESQL,
                    {"query": f"FROM {settings.ELASTIC_AGENT_BUILDER_INDEX_PATTERN.strip()} | LIMIT 1"},
                )
                envelopes = self.json_content(probe)
                sample = [
                    row for envelope in envelopes
                    for row in self._rows_from_payload(envelope)
                ]
                if sample:
                    # Field names only, never sample values/log records.
                    import re
                    indexed_fields = sorted(
                        str(key)[:90] for key in sample[0].keys()
                        if isinstance(key, str)
                        and re.fullmatch(r"[A-Za-z0-9_.@-]{1,90}", key)
                    )[:32]
                index_probe = "has_rows" if sample else (
                    "unrecognized_response" if envelopes and any(
                        isinstance(value, dict) and
                        not (value.get("rows") == [] or value.get("values") == [])
                        for value in envelopes
                    ) else "empty_index"
                )
            except Exception:
                index_probe = "probe_failed"
        status = (
            "candidates_found" if hosts else
            "no_host_metadata" if logs else
            "index_has_rows_no_service_time_match" if index_probe == "has_rows" else
            "response_format_unrecognized" if index_probe == "unrecognized_response" else
            "index_probe_failed" if index_probe == "probe_failed" else
            "no_matching_logs"
        )
        logger.info(
            "elastic_host_discovery_summary",
            service=str(service)[:90],
            index_pattern=settings.ELASTIC_AGENT_BUILDER_INDEX_PATTERN.strip()[:160],
            status=status,
            index_probe=index_probe,
            log_rows=len(logs),
            host_candidates=len(hosts),
        )
        return {
            "status": status,
            "index_pattern": settings.ELASTIC_AGENT_BUILDER_INDEX_PATTERN.strip()[:160],
            "index_probe": index_probe,
            "sample_field_names": indexed_fields,
            "searched_service": service, "result_count": len(logs),
            "candidates": list(hosts.values())[:8],
            "requires_independent_verification": True,
        }
