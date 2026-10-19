"""Conservative classification of downstream dependency-related alert/log signals.

Classification is a reason to check verified application configuration, never
proof that a dependency is broken or permission to scan an arbitrary endpoint.
"""
from __future__ import annotations
import re

_PATTERNS = (
    ("cache", re.compile(r"\bredis\b|\bmemcached\b|ردیس|cache (?:timeout|error|unavailable)", re.I)),
    ("database", re.compile(
        r"\bpostgres(?:ql)?\b|\bpgpool\b|\bmysql\b|\bmariadb\b|\bsqlserver\b|"
        r"\bmssql\b|\boracle\b|\bORA-\d+\b|\bmongodb\b|\bdb2\b|\bcassandra\b|\bneo4j\b|"
        r"(?:database|jdbc|db connection|connection pool).{0,60}"
        r"(?:timeout|failed|refused|exhausted|unavailable|error)", re.I)),
    ("message_broker", re.compile(
        r"\bactivemq\b|\bartemis\b|\brabbitmq\b|\bamqp\b|\bkafka\b|\bnats\b|\bmqtt\b|\bjms\b|"
        r"(?:message broker|message queue).{0,60}"
        r"(?:timeout|failed|refused|unavailable|error)", re.I)),
    # Vendor-neutral transport failures still warrant bounded config discovery.
    # They are hints, not evidence that a specific dependency is unhealthy.
    ("unknown_dependency", re.compile(
        r"\b(?:ECONNREFUSED|ETIMEDOUT|EHOSTUNREACH|ENETUNREACH|"
        r"ENOTFOUND|EAI_AGAIN|SocketException|SSLHandshakeException|"
        r"NameResolutionFailure|DeadlineExceeded|grpc-status[:=]14)\b|"
        r"(?:TLS|SSL) handshake (?:failed|timeout)|"
        r"getaddrinfo (?:failed|error)", re.I)),
    ("http_dependency", re.compile(
        r"(?:http|https|rest|soap|upstream|downstream|api client|external service)"
        r".{0,90}(?:timeout|refused|unavailable|502|503|504|connect(?:ion)? failed|error)"
        r"|(?:connection refused|connect timeout).{0,90}(?:https?|upstream|api)", re.I)),
)
_SOURCES = {"elasticsearch", "prometheus", "zabbix", "vm_mcp"}


def dependency_signals(evidence: list[dict]) -> list[str]:
    found = set()
    for row in evidence[:140]:
        if not isinstance(row, dict):
            continue
        if str(row.get("source") or "").lower() not in _SOURCES:
            continue
        if row.get("type") not in {"alert", "log", "event"}:
            continue
        raw = row.get("raw_data")
        if not isinstance(raw, dict):
            continue
        # Never send these bytes to an LLM or use them as network destinations.
        text = str(raw)[:2400]
        for category, expression in _PATTERNS:
            if expression.search(text):
                found.add(category)
    return sorted(found)


def has_dependency_probe(evidence: list[dict]) -> bool:
    return any(
        isinstance(row, dict) and isinstance(row.get("raw_data"), dict)
        and row["raw_data"].get("diagnostic") == "dependency_investigation"
        for row in evidence[:150]
    )
