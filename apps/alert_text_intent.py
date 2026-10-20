"""Interpret the exact ingress alert message BEFORE consulting advisory tags.

This module identifies the *topic of investigation*, not a root cause.
Values are bounded, deterministic and may never become unverified MCP targets.
"""
from __future__ import annotations

import re
from typing import Any, Mapping

# Ordered from specific technologies to generic transport symptoms. Regexes
# use boundaries so a service identifier cannot accidentally create a topic.
_TOPIC_PATTERNS = (
    ("redis", re.compile(r"\b(?:redis|valkey|keydb|memcached)\b|ردیس", re.I)),
    ("database", re.compile(
        r"\b(?:database|databases|db|dbms|postgres(?:ql)?|mysql|mariadb|"
        r"sql[ _-]?server|mssql|oracle|mongodb?|cassandra|neo4j|db2|jdbc|"
        r"datasource|r2dbc|sqlstate)\b|دیتابیس|پایگاه\s*داده", re.I)),
    ("messaging", re.compile(
        r"\b(?:activemq|artemis|kafka|rabbitmq|amqp|jms|nats|mqtt|"
        r"message[ _-]?broker|message[ _-]?queue|consumer[ _-]?lag|"
        r"dead[ _-]?letter[ _-]?queue|dlq)\b|صف\s*پیام", re.I)),
    ("http", re.compile(
        r"\b(?:http[s]?|grpc|rest[ _-]?api|webhook|upstream[ _-]?api|"
        r"external[ _-]?api|soap)\b", re.I)),
    ("disk", re.compile(r"\b(?:disk|inode|filesystem|mount|volume[ _-]?full)\b|دیسک", re.I)),
    ("memory", re.compile(r"\b(?:memory|ram|swap|out[ _-]?of[ _-]?memory|oom)\b|حافظه", re.I)),
    ("cpu", re.compile(r"\b(?:cpu|processor|load[ _-]?average)\b|پردازنده", re.I)),
    ("service", re.compile(
        r"\b(?:systemd|service[ _-]?(?:down|failed|stopped|crashed)|"
        r"process[ _-]?(?:died|failed|stopped)|crashloopbackoff)\b", re.I)),
    ("network", re.compile(
        r"\b(?:network|dns|tcp|packet[ _-]?loss|connection[ _-]?refused|"
        r"route[ _-]?unreachable)\b|شبکه", re.I)),
)
_ROUTE = {
    "redis": "dependency", "database": "database", "messaging": "messaging",
    "http": "dependency", "disk": "storage", "memory": "infrastructure",
    "cpu": "infrastructure", "service": "vm", "network": "network",
}
_TAG_FAMILIES = {
    "database": "database", "db": "database", "postgres": "database",
    "postgresql": "database", "mysql": "database", "mariadb": "database",
    "mssql": "database", "sqlserver": "database", "oracle": "database",
    "mongodb": "database", "cassandra": "database", "neo4j": "database",
    "kafka": "messaging", "activemq": "messaging", "artemis": "messaging",
    "rabbitmq": "messaging", "amqp": "messaging", "broker": "messaging",
    "messaging": "messaging", "nats": "messaging", "mqtt": "messaging",
    "redis": "redis", "valkey": "redis", "keydb": "redis",
    "http": "http", "https": "http", "grpc": "http",
    "disk": "disk", "cpu": "cpu", "memory": "memory", "network": "network",
}
_CONDITIONS = (
    ("connection_refused", re.compile(r"\b(?:connection refused|econnrefused)\b", re.I)),
    ("connection_timeout", re.compile(
        r"\b(?:(?:connect(?:ion)?|socket)\s+timed?\s*out|"
        r"(?:connect(?:ion)?|socket)\s+timeout|etimedout)\b", re.I)),
    ("authentication_error", re.compile(
        r"\b(?:authentication failed|login failed|access denied|invalid credentials)\b", re.I)),
    ("pool_exhaustion", re.compile(
        r"\b(?:connection pool exhausted|pool exhaustion|too many connections)\b", re.I)),
    ("error_threshold", re.compile(
        r"\b(?:errors?|failures?)\b.{0,55}\b(?:reached|exceeded|at least|threshold)\b"
        r"|\b(?:reached|exceeded|at least)\b.{0,45}\b(?:errors?|failures?|events?)\b", re.I)),
    ("error_reported", re.compile(r"\b(?:errors?|failures?|exceptions?)\b|خطا", re.I)),
)
_NEGATIVE = re.compile(r"\b(?:no|zero|without)\s+(?:\w+\s+){0,4}(?:errors?|failures?|issues?)\b", re.I)


def topic_from_tag(value: Any) -> str:
    return _TAG_FAMILIES.get(str(value or "").strip().lower(), "")


def analyze_alert_text(text: Any, *, dependency_tag: Any = None) -> dict[str, Any]:
    """Return a bounded, explainable investigation topic; not service health."""
    message = str(text or "")[:1400]
    # Direct matches, rather than loose substring checks on entire log/VM data.
    candidates = [name for name, regex in _TOPIC_PATTERNS if regex.search(message)]
    # 'connection' and 'network' are secondary transport symptoms when a DB,
    # broker or Redis was explicitly identified in the original alarm.
    if len(candidates) > 1 and "network" in candidates:
        candidates.remove("network")
    # A service name itself is not the described failure when an explicit
    # dependency technology appears.
    if len(candidates) > 1 and "service" in candidates:
        candidates.remove("service")
    # HTTP transport may be a symptom of a more explicit named dependency.
    if len(candidates) > 1 and "http" in candidates:
        candidates.remove("http")
    negative = bool(_NEGATIVE.search(message))
    tag_family = topic_from_tag(dependency_tag)
    # The text wins when unambiguous. Tags help only when the text has no
    # explicit family. Contradictions must be visible, never silently merged.
    if negative:
        family, basis = "other", "negative_alert_text"
    elif len(candidates) == 1:
        family, basis = candidates[0], "alert_text"
    elif len(candidates) > 1:
        family, basis = "other", "ambiguous_alert_text"
    elif tag_family:
        family, basis = tag_family, "tag_fallback"
    else:
        family, basis = "other", "unclassified"
    condition = next(
        (name for name, regex in _CONDITIONS if regex.search(message)), "unspecified"
    )
    return {
        "family": family,
        "route": _ROUTE.get(family, ""),
        "condition": condition if not negative else "no_reported_error",
        "basis": basis,
        "candidate_families": candidates[:4],
        "tag_family": tag_family,
        "tag_conflict": bool(tag_family and candidates and tag_family not in candidates),
        "symptom_only": True,
        "root_cause_confirmed": False,
    }


def received_alert_intents(raw_evidence: list, service_name: str) -> list[dict]:
    """Analyze ingress notification text for *exactly* the reported service.

    A log, MCP diagnostic, LLM inference, unrelated-service event or unsourced
    arbitrary instruction can never become a routing directive.
    """
    service = str(service_name or "").strip()
    if not service or len(service) > 128:
        return []
    intents: list[dict] = []
    for item in raw_evidence[:80]:
        if not isinstance(item, Mapping):
            continue
        if str(item.get("source") or "").lower() not in {
            "zabbix", "prometheus", "elasticsearch", "kubernetes",
        } or str(item.get("type") or "").lower() != "alert":
            continue
        raw = item.get("raw_data")
        if not isinstance(raw, Mapping):
            continue
        data = raw.get("payload") if isinstance(raw.get("payload"), Mapping) else raw
        tags = data.get("tags")
        tag_map = {
            str(row.get("tag") or "").lower(): str(row.get("value") or "")
            for row in tags[:40] if isinstance(row, Mapping)
        } if isinstance(tags, list) else {}
        declared = str(data.get("service") or tag_map.get("service") or "").strip()
        if declared and declared.casefold() != service.casefold():
            continue
        # Source-bound text only, not arbitrary context/LLM interpretation.
        title = next((
            value for value in (
                data.get("name"), data.get("trigger"), data.get("alertname"),
                data.get("signal_summary"), item.get("message"),
                data.get("operational_data"),
                data.get("message"),
            ) if isinstance(value, str) and value.strip()
        ), "")
        # When service metadata is absent, the complete source title itself
        # must explicitly identify the requested service to avoid cross-talk.
        if not declared and not re.search(
            r"(?<![A-Za-z0-9_])" + re.escape(service) + r"(?![A-Za-z0-9_])",
            title, re.I,
        ):
            continue
        tag = tag_map.get("dependency") or data.get("dependency")
        intent = analyze_alert_text(title, dependency_tag=tag)
        if intent["basis"] == "negative_alert_text":
            continue
        intent["evidence_ref"] = str(item.get("reference") or item.get("id") or "")[:120]
        intent["reported_service"] = service
        intent["source"] = str(item.get("source") or "")[:30]
        # Never transmit the entire title in diagnostic/structured routing;
        # the original is already stored intact as ingress evidence.
        intents.append(intent)
        if len(intents) >= 6:
            break
    return intents
