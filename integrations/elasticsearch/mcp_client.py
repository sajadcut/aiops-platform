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
        """Decode bounded tabular ES|QL envelopes from Kibana Agent Builder MCP.

        Some deployments return the tabular JSON as a nested *string* in
        structuredContent.result or a content.text item rather than as an
        object. Parsing a string is data-only; it is never executed and never
        logged. Unrecognized formats remain non-authoritative.
        """
        import json

        def decode(value: Any, depth: int) -> list[dict[str, Any]]:
            if depth > 6:
                return []
            if isinstance(value, str):
                candidate = value.strip()
                if not (candidate.startswith("{") or candidate.startswith("[")):
                    return []
                if len(candidate) > 500_000:
                    return []
                try:
                    return decode(json.loads(candidate), depth + 1)
                except (ValueError, TypeError):
                    return []
            if isinstance(value, list):
                rows: list[dict[str, Any]] = []
                for item in value[:20]:
                    rows.extend(decode(item, depth + 1))
                    if len(rows) >= 500:
                        break
                return rows[:500]
            if not isinstance(value, dict):
                return []
            columns = value.get("columns")
            data_rows = value.get("values")
            if data_rows is None:
                data_rows = value.get("rows")
            if isinstance(columns, list) and isinstance(data_rows, list):
                names = [
                    str(column.get("name") or "") if isinstance(column, dict)
                    else str(column)
                    for column in columns[:100]
                ]
                return [
                    ({name: row[i] if i < len(row) else None
                      for i, name in enumerate(names)}
                     if isinstance(row, list) else row)
                    for row in data_rows[:500] if isinstance(row, (list, dict))
                ]
            rows = value.get("rows")
            if isinstance(rows, list) and all(isinstance(row, dict) for row in rows):
                return rows[:500]
            for key in ("result", "data", "structuredContent", "results",
                        "content", "json", "text", "output", "response"):
                decoded = decode(value.get(key), depth + 1)
                if decoded:
                    return decoded
            return []
        return decode(payload, 0)

    @staticmethod
    def _esql_empty_table(payload: Any, depth: int = 0) -> bool:
        """Recognize an ES|QL *empty table*, including JSON-text MCP envelopes.

        Do not conflate a metadata-only success response with an empty query.
        Only explicit rows=[] or values=[] establish a recognized empty table.
        """
        if depth > 6:
            return False
        if isinstance(payload, str):
            candidate = payload.strip()
            if len(candidate) > 500_000 or not candidate.startswith(("{", "[")):
                return False
            try:
                import json
                return ElasticsearchMCPClient._esql_empty_table(
                    json.loads(candidate), depth + 1,
                )
            except (ValueError, TypeError):
                return False
        if isinstance(payload, list):
            # A nonempty list of MCP content blocks can all encode empty tables.
            return bool(payload) and all(
                ElasticsearchMCPClient._esql_empty_table(item, depth + 1)
                for item in payload[:20]
            )
        if not isinstance(payload, dict):
            return False
        if payload.get("rows") == [] or payload.get("values") == []:
            return True
        for key in ("result", "data", "results", "structuredContent",
                    "content", "text", "json", "output", "response"):
            value = payload.get(key)
            if value is not None and ElasticsearchMCPClient._esql_empty_table(
                value, depth + 1,
            ):
                return True
        return False

    def _esql_payloads(self, result: dict[str, Any]) -> list[Any]:
        """Prefer a real tabular response over metadata-only structuredContent.

        Kibana may return metadata in structuredContent and the actual rows in
        content[].text. Generic MCP json_content prioritizes structuredContent;
        this Elastic-only adapter can safely inspect the alternate content
        without sending its untrusted text to an LLM.
        """
        primary = self.json_content(result)
        if any(self._rows_from_payload(value) or self._esql_empty_table(value)
               for value in primary):
            return primary
        parts = result.get("content")
        if isinstance(parts, list):
            for part in parts[:10]:
                if isinstance(part, dict) and (
                    self._rows_from_payload(part) or self._esql_empty_table(part)
                ):
                    return [part]
        return primary

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
        schema_field_names: Optional[list[str]] = None,
    ) -> List[LogEntry]:
        bounded_limit = min(max(int(limit), 1), 500)
        end = until or datetime.now(timezone.utc)
        # Operator-configured aliases only; never infer GFP_Backend == gfpapi.
        aliases = getattr(settings, "ELASTIC_SERVICE_DISCOVERY_ALIASES", {}) or {}
        values = aliases.get(service, []) if isinstance(aliases, dict) else []
        names = [service]
        if isinstance(values, list):
            for alias in values[:4]:
                if isinstance(alias, str) and alias.strip() and alias.strip().casefold() not in {
                        s.casefold() for s in names}:
                    names.append(alias.strip())
        # An operator might declare the canonical unit -> Elastic label instead
        # of label -> unit. Reverse only a unique explicit relationship.
        reverse = [
            str(owner).strip() for owner, entries in aliases.items()
            if isinstance(entries, list) and any(
                str(item).strip().casefold() == str(service).strip().casefold()
                for item in entries)
        ] if isinstance(aliases, dict) else []
        if len(reverse) == 1 and reverse[0].casefold() not in {
                name.casefold() for name in names}:
            names.append(reverse[0])
        names = names[:5]
        lower = self._esql_string(since.astimezone(timezone.utc).isoformat())
        upper = self._esql_string(end.astimezone(timezone.utc).isoformat())
        # Use the sample document's COLUMN NAMES only to select a
        # deterministic schema-specific query. A generic ECS lookup is still
        # used where no index schema was observed.
        available = set(schema_field_names or [])
        if schema_field_names is None:
            fields = ("service.name", "service", "Properties.ServiceName.keyword",
                      "Properties.ServiceName", "service.name.keyword")
            time_fields = ("@timestamp",)
            observed_hosts: tuple[str, ...] = ()
        else:
            fields = tuple(field for field in (
                "Properties.ServiceName.keyword", "Properties.ServiceName",
                "Properties.ApplicationName.keyword", "Properties.ApplicationName",
                "service.name.keyword", "service.name", "service",
                "Properties.ServiceId.keyword", "Properties.ServiceId",
            ) if field in available)
            time_fields = tuple(field for field in ("@timestamp", "Timestamp")
                                if field in available)
            observed_hosts = tuple(field for field in (
                "Properties.MachineName", "host.name", "host.ip", "agent.hostname"
            ) if field in available)
        index_pattern = settings.ELASTIC_AGENT_BUILDER_INDEX_PATTERN.strip()
        rows: list[dict[str, Any]] = []
        succeeded = 0
        unrecognized_payloads = 0
        last_error: Exception | None = None
        recognized_empty_envelopes = 0
        for name in names:
            for field in fields:
                for time_field in time_fields:
                    quoted_time = time_field if time_field == "@timestamp" else f"`{time_field}`"
                    clauses = [
                        f"{quoted_time} >= TO_DATETIME({lower})",
                        f"{quoted_time} <= TO_DATETIME({upper})",
                        f"`{field}` == {self._esql_string(name)}",
                    ]
                    if level and (schema_field_names is None or "log.level" in available):
                        clauses.append(f"`log.level` == {self._esql_string(level)}")
                    if schema_field_names is not None:
                        # No guessing missing fields on this schema path. Keep
                        # just existing fields, not a broad unfiltered scan.
                        keep = [quoted_time]
                        if "message" in available:
                            keep.append("message")
                        keep.extend(f"`{value}`" for value in observed_hosts[:4])
                        keep.append(f"`{field}`")
                        projections = (", ".join(dict.fromkeys(keep)),)
                    else:
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
                            + f" | SORT {quoted_time} DESC | KEEP " + projection
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
                    payloads = self._esql_payloads(result)
                    for payload in payloads:
                        decoded = self._rows_from_payload(payload)
                        if not decoded:
                            if self._esql_empty_table(payload):
                                recognized_empty_envelopes += 1
                            else:
                                unrecognized_payloads += 1
                        rows.extend(decoded)
                    if rows:
                        break
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
            recognized_empty_envelopes=recognized_empty_envelopes,
            observed_schema_lookup=schema_field_names is not None,
        )
        self._last_esql_query_diagnostics = {
            "success_count": succeeded,
            "decoded_rows": len(rows),
            "unrecognized_envelopes": unrecognized_payloads,
            "recognized_empty_envelopes": recognized_empty_envelopes,
            "schema_lookup": schema_field_names is not None,
        }
        if not succeeded and last_error is not None:
            raise RuntimeError("elastic_all_service_field_queries_failed") from last_error

        logs: List[LogEntry] = []
        for item in rows:
            raw_ts = item.get("@timestamp") or item.get("Timestamp") or item.get("timestamp")
            try:
                timestamp = datetime.fromisoformat(str(raw_ts).replace("Z", "+00:00")) if raw_ts else datetime.now(timezone.utc)
            except (ValueError, TypeError):
                timestamp = datetime.now(timezone.utc)
            service_value = item.get("service")
            if isinstance(service_value, dict):
                service_value = service_value.get("name")
            logs.append(LogEntry(
                timestamp=timestamp,
                service=str(service_value or item.get("service.name") or item.get("Properties.ServiceName.keyword") or item.get("Properties.ServiceName") or item.get("Properties.ApplicationName.keyword") or item.get("Properties.ApplicationName") or service),
                level=str(item.get("level") or (item.get("log") or {}).get("level") or "info"),
                message=str(item.get("message") or item.get("Properties.LogEntry.Message") or ""),
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
        initial_diagnostics = dict(getattr(self, "_last_esql_query_diagnostics", {}) or {})
        index_probe = "not_needed"
        indexed_fields: list[str] = []
        attempted_observed_schema = False
        if not logs:
            # Diagnostic sample is used exclusively for known COLUMN NAMES.
            # Never bind a VM directly from an unfiltered index document.
            try:
                probe = await self.call_tool(
                    self.TOOL_EXECUTE_ESQL,
                    {"query": f"FROM {settings.ELASTIC_AGENT_BUILDER_INDEX_PATTERN.strip()} | LIMIT 1"},
                )
                envelopes = self._esql_payloads(probe)
                sample = [row for envelope in envelopes
                          for row in self._rows_from_payload(envelope)]
                if sample:
                    import re
                    indexed_fields = sorted(
                        str(key)[:90] for key in sample[0]
                        if isinstance(key, str)
                        and re.fullmatch(r"[A-Za-z0-9_.@-]{1,90}", key)
                    )[:128]
                index_probe = "has_rows" if sample else (
                    "unrecognized_response" if envelopes and any(
                        not self._esql_empty_table(value) for value in envelopes
                    ) else "empty_index")
            except Exception as exc:
                index_probe = "probe_failed"
                logger.warning("elastic_schema_probe_failed",
                               error_type=type(exc).__name__)

            if (index_probe == "has_rows" and
                    any(key in indexed_fields for key in (
                        "Properties.ServiceName", "Properties.ServiceName.keyword",
                        "Properties.ApplicationName", "Properties.ApplicationName.keyword",
                        "service.name", "service", "Properties.ServiceId")) and
                    any(key in indexed_fields for key in ("@timestamp", "Timestamp")) and
                    any(key in indexed_fields for key in (
                        "Properties.MachineName", "host.name", "host.ip",
                        "agent.hostname", "HostName", "hostname"))):
                attempted_observed_schema = True
                try:
                    logs = await self.get_logs(
                        service, since, until, limit=40,
                        schema_field_names=indexed_fields)
                except Exception as exc:
                    logger.warning("elastic_observed_schema_lookup_failed",
                                   error_type=type(exc).__name__)
        observed_diagnostics = dict(getattr(self, "_last_esql_query_diagnostics", {}) or {})
        hosts: dict[str, dict[str, Any]] = {}
        import ipaddress
        for log in logs:
            raw = log.raw_data if isinstance(log.raw_data, dict) else {}
            host = raw.get("host")
            if not isinstance(host, dict):
                host = {}
            # Serilog commonly emits Properties.MachineName while ECS uses
            # host.name or host.ip. agent.hostname identifies the collector,
            # so prefer an application machine field where available.
            hostname = str(
                raw.get("Properties.MachineName")
                or raw.get("host.name") or host.get("name")
                or raw.get("agent.hostname") or ""
            ).strip()
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
        # If the MCP responded with a non-tabular envelope, report a parsing
        # ambiguity, NOT a definite empty service/time result.
        # Report the final schema-specific attempt when it ran, rather than
        # carrying an old generic-schema parsing miss as the outcome.
        final_diagnostics = (
            observed_diagnostics if attempted_observed_schema
            and observed_diagnostics.get("schema_lookup")
            else initial_diagnostics
        )
        unknown_rows = int(final_diagnostics.get("unrecognized_envelopes") or 0)
        recognized_empty = int(final_diagnostics.get("recognized_empty_envelopes") or 0)
        status = (
            "candidates_found" if hosts else
            "no_host_metadata" if logs else
            "response_format_unrecognized" if unknown_rows > 0 else
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
            observed_schema_lookup=attempted_observed_schema,
            unrecognized_envelopes=unknown_rows,
            recognized_empty_envelopes=recognized_empty,
        )
        return {
            "status": status,
            "index_pattern": settings.ELASTIC_AGENT_BUILDER_INDEX_PATTERN.strip()[:160],
            "index_probe": index_probe,
            "sample_field_names": indexed_fields[:32],
            "observed_schema_lookup": attempted_observed_schema,
            "unrecognized_envelopes": unknown_rows,
            "recognized_empty_envelopes": recognized_empty,
            "searched_service": service, "result_count": len(logs),
            "candidates": list(hosts.values())[:8],
            "requires_independent_verification": True,
        }
