"""Alert-specific DB/broker error correlation by AIOps central model.

This is a diagnostic hypothesis only: a synthetic monitoring signal does not
prove a database failure, and TCP is not SQL login/query verification.
The model sees only bounded allowlisted error signatures and verified
transport observations; never full journal lines, SQL or credentials.
"""
from __future__ import annotations

import asyncio
from collections import Counter
from datetime import datetime, timezone
import ipaddress
import json
import re
from typing import Any

from domain.contracts.config import settings
from domain.contracts.redaction import redact

_KINDS = {
    "database": frozenset({"postgres", "postgresql", "mysql", "mariadb", "mssql",
        "sqlserver", "oracle", "mongodb", "db2", "cassandra", "neo4j", "database_tcp"}),
    "message_broker": frozenset({"activemq", "rabbitmq", "kafka", "amqp", "nats", "mqtt"}),
    "cache": frozenset({"redis", "valkey", "keydb"}),
}
_SIGNATURES = {
    "pool_exhaustion": re.compile(r"pool (?:is )?exhausted|connection pool|too many connections|pooltimeout|timeout while getting a connection", re.I),
    "authentication_failed": re.compile(r"login failed|authentication failed|password authentication failed|access denied|invalid credentials|ORA-01017", re.I),
    "connection_refused": re.compile(r"connection refused|ECONNREFUSED|actively refused|connectexception", re.I),
    "connection_timeout": re.compile(r"connect(?:ion)?(?:ion)? timeout|ETIMEDOUT|SocketTimeoutException|timed out|timeout expired", re.I),
    "name_resolution_failed": re.compile(r"no such host|name or service not known|EAI_AGAIN|ENOTFOUND|unknown host|ORA-12154", re.I),
    "tls_handshake_failed": re.compile(r"SSLHandshakeException|certificate verify failed|tls handshake|ssl handshake", re.I),
    "connection_reset": re.compile(r"connection reset|ECONNRESET|broken pipe", re.I),
    "db_connection_error": re.compile(r"SQLSTATE|NpgsqlException|SqlException|psycopg|JDBCConnectionException|ORA-\d{5}|MongoConnectionException", re.I),
    "broker_connection_error": re.compile(r"broker unavailable|kafkaexception|JMSException|amqpconnectionexception", re.I),
}
# Without a DB-specific log phrase, a generic timeout may concern some
# unrelated HTTP/Redis call and must not be attached to the database alert.
_DB_ANCHOR = re.compile(
    r"database|postgres|sql|jdbc|npgsql|mysql|mongo|oracle|ora-\d+|"
    r"dbconnection|dbcontext|connection pool|data source|psycopg|cassandra", re.I
)
_MQ_ANCHOR = re.compile(r"kafka|activemq|rabbitmq|broker|queue|topic|jms|amqp|nats|mqtt", re.I)
_CACHE_ANCHOR = re.compile(r"redis|valkey|keydb", re.I)
_ALLOWED = {"network", "authentication", "pool", "dns", "tls", "protocol", "unknown"}


def _error_signatures(evidence: list[dict], family: str, service: str) -> tuple[list[dict], dict]:
    anchor = (
        _DB_ANCHOR if family == "database" else
        _MQ_ANCHOR if family == "message_broker" else _CACHE_ANCHOR
    )
    counts: Counter[tuple[str, str]] = Counter()
    references: dict[tuple[str, str], str] = {}
    log_inputs = 0
    searched = 0
    unparsable = 0
    for item in evidence[:160]:
        if not isinstance(item, dict):
            continue
        raw = item.get("raw_data")
        if not isinstance(raw, dict):
            continue
        source = str(item.get("source") or "")
        if source == "elasticsearch" and raw.get("query_service"):
            searched += 1
            if raw.get("status") == "error" and (
                raw.get("detail") == "response_format_unrecognized"
                or raw.get("error_code") == "response_format_unrecognized"
            ):
                unparsable += 1
        if source not in {"elasticsearch", "vm_mcp"} or item.get("type") != "log":
            continue
        observed = str(raw.get("service") or raw.get("Properties.ServiceName")
                       or raw.get("service.name") or "").strip()
        # An unscoped log line can describe another service on the same VM.
        # Require an explicit matching service label. For VM journal entries,
        # only an independently service-bound query may establish the source.
        # Without either, refuse to attribute the error to this alert.
        if observed.casefold().removesuffix(".service") != service.casefold().removesuffix(".service"):
            continue
        entries = raw.get("entries") if isinstance(raw.get("entries"), list) else [
            raw.get("message") or raw.get("Message") or raw.get("Properties.LogEntry.Message")
        ]
        for line in entries[:100]:
            if not isinstance(line, str):
                continue
            log_inputs += 1
            if not anchor.search(line[:1200]):
                continue
            for code, pattern in _SIGNATURES.items():
                if pattern.search(line[:1200]):
                    key = (source, code)
                    counts[key] += 1
                    references[key] = str(item.get("reference") or item.get("id") or "")[:180]
    records = [
        {"source": src, "error_signature": sig, "count": min(count, 100),
         "evidence_ref": references[(src, sig)]}
        for (src, sig), count in counts.most_common(18)
    ]
    return records, {
        "log_records_inspected": min(log_inputs, 1000),
        "elastic_queries_recorded": searched,
        "elastic_unrecognized_responses": unparsable,
    }


async def analyze_dependency_logs(
    *, service: str, family: str, evidence: list[dict], probe: dict,
    adapter: Any = None,
) -> dict:
    """Bounded, read-only central LLM analysis; never authorizes remediation."""
    signatures, diagnostics = _error_signatures(evidence, family, service)
    relevant = [
        {
            "kind": str(row.get("kind") or "")[:32],
            "host": str(row.get("host") or "")[:120],
            "port": row.get("port"),
            "tcp_reachable": row.get("tcp_reachable")
                if type(row.get("tcp_reachable")) is bool else None,
            "probe_status": str(row.get("probe_status") or "")[:55],
            "port_inferred": row.get("port_inferred"),
        }
        for row in (probe.get("dependencies") or [])[:6]
        if isinstance(row, dict) and row.get("kind") in _KINDS.get(family, ())
    ]
    model_status = "not_required"
    hypothesis = "unknown"
    narrative = ""
    if signatures or relevant:
        model_status = "central_llm_unavailable"
        if adapter is None and settings.LLM_BASE_URL and settings.LLM_MODEL:
            try:
                from integrations.llm.openai_compatible import configured_llm_adapter
                adapter = configured_llm_adapter()
            except Exception:
                adapter = None
        if adapter is not None:
            try:
                response = await asyncio.wait_for(
                    adapter.generate_with_messages(
                        [{"role": "system", "content": (
                            "As an SRE, analyze only the supplied error signature counts "
                            "and independently verified transport probes for the EXACT "
                            "alert service and dependency family. Error signatures are "
                            "application log observations, not proof of root cause. "
                            "A TCP connection never verifies database authentication "
                            "or a SQL query. When zero matching logs/endpoints exist, "
                            "the incident cause is unverified. No invented host, port, "
                            "code, test, action or successful operation. "
                            'Return ONLY JSON {"hypothesis":"unknown",'
                            '"analysis_fa":"توضیح فنی کوتاه و محتاطانه."}. '
                            "hypothesis must be network, authentication, pool, "
                            "dns, tls, protocol or unknown. This does not authorize changes."
                        )}, {"role": "user", "content": json.dumps({
                            "alert_service": service, "dependency_family": family,
                            "error_signatures": signatures,
                            "endpoint_transport_checks": relevant,
                            **diagnostics,
                        }, ensure_ascii=False)}],
                        stage="central_dependency_error_correlation",
                        temperature=0.0, max_tokens=280,
                    ), timeout=12.0,
                )
                parsed = json.loads(str(getattr(response, "content", "") or "").strip())
                text = str(parsed.get("analysis_fa") or "").strip()
                candidate = str(parsed.get("hypothesis") or "")
                allowed_hosts = {row["host"] for row in relevant}
                ip_mentions = re.findall(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])", text)
                signature_codes = {row["error_signature"] for row in signatures}
                hypothesis_supported = (
                    candidate == "unknown"
                    or candidate == "authentication"
                       and "authentication_failed" in signature_codes
                    or candidate == "pool"
                       and "pool_exhaustion" in signature_codes
                    or candidate == "tls"
                       and "tls_handshake_failed" in signature_codes
                    or candidate == "dns"
                       and "name_resolution_failed" in signature_codes
                    or candidate == "network"
                       and (
                           "connection_refused" in signature_codes
                           or "connection_timeout" in signature_codes
                           or "connection_reset" in signature_codes
                           or any(row["tcp_reachable"] is False for row in relevant)
                       )
                    or candidate == "protocol"
                       and bool(signature_codes & {
                           "db_connection_error", "broker_connection_error",
                       })
                )
                if (candidate in _ALLOWED and hypothesis_supported
                        and 20 <= len(text) <= 650
                        and not any(host not in allowed_hosts for host in ip_mentions)
                        and not re.search(r"علت\s+قطعی\s+(?:است|مشخص|تأیید\s+شده)|قطعاً\s+مشخص|ریشه\s+تأیید\s+شده", text)):
                    hypothesis = candidate
                    narrative = str(redact(text))
                    model_status = "llm_analyzed"
                else:
                    model_status = "llm_output_rejected"
            except Exception:
                model_status = "central_llm_unavailable"
    if not narrative:
        narrative = (
            "هیچ خطای دیتابیسی یا مقصد تأییدشده‌ای در شواهد موجود شناسایی نشد؛ "
            "علت آلارم صرفاً بر اساس متن اعلان قابل تأیید نیست."
            if not signatures and not relevant else
            "شواهد ارتباطی و امضاهای خطای برنامه ثبت شده‌اند، اما "
            "علت قطعی بدون تطبیق زمان، کانفیگ مؤثر و تست اختصاصی تأیید نشده است."
        )
    return {
        "type": "telemetry", "source": "aiops_analysis",
        "reference": f"dependency-log-analysis:{family}:{service}"[:180],
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "raw_data": {
            "server": "aiops_llm", "diagnostic": "dependency_error_log_analysis",
            "service": service[:120], "family": family,
            "model_status": model_status, "hypothesis": hypothesis,
            "summary": narrative, "error_signatures": signatures,
            "matching_endpoint_count": len(relevant),
            **diagnostics,
            "root_cause_confirmed": False, "read_only": True,
            "execution_authority": False,
        },
    }
