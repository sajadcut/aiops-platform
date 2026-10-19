"""Deterministic, read-only answer to the *received alert*, not a generic VM summary.

Only durable ingress notifications and already-serialized MCP evidence are read.
A matching diagnostic is not proof that the alert's root cause is established.
No remote calls, LLM decisions, credentials, or execution authority are involved.
"""
from __future__ import annotations

import re
from typing import Any

from apps.received_signal_view import project_received_signal
from domain.contracts.redaction import redact

# Open-ended alerts still get a sourced answer. These families only guide
# ordering of checks; they never identify a service or authorize a target.
_FAMILIES = (
    ("redis", r"\bredis\b|\bkeydb\b|\bvalkey\b"),
    ("database", r"\bdatabase\b|\bdb\b|\bpostgres(?:ql)?\b|\bmysql\b|\bmaria(?:db)?\b|\bmongo(?:db)?\b|\bmssql\b|\bsql[ _-]?server\b|\boracle\b|پایگاه\s*داده|دیتابیس"),
    ("messaging", r"\bactivemq\b|\brabbitmq\b|\bkafka\b|\bmessage[ _-]?broker\b|\bqueue\b|\bamqp\b|صف\s*پیام"),
    ("http", r"\bhttp[s]?\b|\bapi\b|\bupstream\b|\bendpoint\b|\bgrpc\b|\bwebhook\b|\burl\b|وب\s*سرویس"),
    ("disk", r"\bdisk\b|\bfilesystem\b|\binode\b|\bstorage\b|\bmount\b|دیسک|فضای\s*ذخیره"),
    ("memory", r"\bmemory\b|\bram\b|\boom\b|\bswap\b|حافظه"),
    ("cpu", r"\bcpu\b|\bprocessor\b|\bload average\b|پردازنده"),
    ("service", r"\bsystemd\b|\bservice\s+(?:down|failed|stopped|inactive|crash)|\bprocess\s+(?:died|failed|stopped)|سرویس\s*(?:قطع|متوقف|خاموش)"),
    ("network", r"\bdns\b|\btcp\b|\bnetwork\b|\bconnection\b|\broute\b|\bpacket loss\b|شبکه|اتصال"),
)
_TOOL_FAMILIES = {
    "redis": {"redis_dependency_check", "dependency_investigation"},
    "database": {"dependency_investigation"},
    "messaging": {"dependency_investigation"},
    "http": {"dependency_investigation", "http_check", "http_head"},
    "disk": {"disk_status", "disk_forensics"},
    "memory": {"memory_diagnostics", "collect_vm_metrics", "process_snapshot"},
    "cpu": {"collect_vm_metrics", "process_snapshot"},
    "service": {"service_status", "process_status", "service_runtime_discovery", "port_listener_status"},
    "network": {"tcp_check", "dns_check", "route_check", "network_status", "dependency_investigation"},
}
_KIND_FAMILY = {
    "redis": "redis", "valkey": "redis", "keydb": "redis",
    "postgres": "database", "postgresql": "database", "mysql": "database",
    "mariadb": "database", "mongodb": "database", "mssql": "database",
    "sqlserver": "database", "oracle": "database",
    "activemq": "messaging", "rabbitmq": "messaging", "kafka": "messaging",
    "amqp": "messaging", "http": "http", "https": "http", "grpc": "http",
}
_FOLLOWUPS_FA = {
    "redis": "خطاهای اتصال کلاینت برنامه، تنظیمات Endpoint/TLS/Auth، Timeout و Connection Pool را با زمان آلارم تطبیق دهید.",
    "database": "لاگ خطای اتصال برنامه، Endpoint دیتابیس، احراز هویت، Timeout و Pool را با زمان آلارم تطبیق دهید.",
    "messaging": "وضعیت Broker، اتصال مصرف‌کننده/تولیدکننده، صف‌ها و خطاهای زمان آلارم را بررسی کنید.",
    "http": "Endpoint تأییدشده، DNS/TLS، کد پاسخ و Timeout درخواست واقعی برنامه را با آلارم تطبیق دهید.",
    "disk": "مصرف دیسک و inode، وضعیت Mount و روند پرشدن را در بازه آلارم بررسی کنید.",
    "memory": "فشار حافظه، OOM، Swap و روند مصرف را با بازه آلارم مقایسه کنید.",
    "cpu": "روند CPU، Load، Queue و زمان وقوع آلارم را مقایسه کنید.",
    "service": "وضعیت واقعی Unit، MainPID، Journal و زمان وقوع آلارم را تطبیق دهید.",
    "network": "DNS، مسیر، TCP و Timeout بین سرویس مصرف‌کننده و مقصد تأییدشده را بررسی کنید.",
    "other": "براساس متن دقیق آلارم، آزمون مرتبط را با ابزار فقط‌خواندنی انجام دهید و Evidence آن را ثبت کنید.",
}


def _text(value: Any, length: int = 420) -> str:
    if not isinstance(value, str):
        return ""
    return str(redact(value)).replace("\r", " ").replace("\n", " ").strip()[:length]


def _family(message: str) -> str:
    return next((name for name, pattern in _FAMILIES
                 if re.search(pattern, message, flags=re.I)), "other")


def _kind_matches(family: str, checks: list[dict]) -> bool:
    return any(_KIND_FAMILY.get(str(row.get("kind") or "").lower()) == family
               for row in checks if isinstance(row, dict))


_GENERIC_WORDS = frozenset({
    "service", "server", "error", "errors", "failed", "failure", "unknown",
    "unavailable", "status", "incident", "warning", "critical", "alert",
    "problem", "events", "system", "check", "query", "result", "observed",
    "application", "monitoring", "production", "host", "metric",
})


def _topic_tokens(text: str) -> set[str]:
    return {
        token for token in re.findall(r"[a-z][a-z0-9_.-]{5,}", text.lower())
        if token not in _GENERIC_WORDS and not token.isdigit()
    }


def _shares_alert_topic(alert: str, text: str) -> bool:
    return bool(_topic_tokens(alert) & _topic_tokens(text))


def _is_relevant(family: str, tool: str, finding: str, checks: list[dict],
                 alert: str) -> bool:
    # A dependency investigation mentioning a *different* endpoint is not
    # evidence for a Redis/database/broker alarm on the same shared VM.
    if family in {"redis", "database", "messaging", "http"}:
        if tool == "dependency_investigation":
            if checks:
                return _kind_matches(family, checks)
            return _family(finding) == family
        if family == "redis" and tool == "redis_dependency_check":
            return True
        if family == "http" and tool in {"http_check", "http_head"}:
            return True
        # Log search is relevant only if the finding actually describes this
        # technology; a generic successful ELK query proves nothing.
        return bool(finding and _family(finding) == family
                    and tool in {"service_logs", "system_logs", "source_observation"})
    if tool in _TOOL_FAMILIES.get(family, set()):
        return True
    if family == "other":
        # Open-ended technology families (Hazelcast, custom runtimes, etc.)
        # can still match *explicit* unusual tokens in a diagnostic, without
        # turning unrelated systemd checks into verification of the alert.
        return bool(tool in {"dependency_investigation", "service_logs",
                             "system_logs", "source_observation"}
                    and finding and _shares_alert_topic(alert, finding))
    return False


def build_alert_focused_report(incident: dict, evidence: list[dict],
                               brief: dict) -> dict:
    """Produce a mandatory, alert-scoped operator response for every incident."""
    ingress = []
    for record in evidence[:500]:
        if not isinstance(record, dict):
            continue
        view = project_received_signal(record)
        if view is not None and view.get("message"):
            ingress.append(view)
    # Preserve the first problem that triggered the incident. A later recovery
    # notification must not silently overwrite the original problem statement.
    ingress.sort(key=lambda item: str(item.get("received_at") or ""))
    problems = [item for item in ingress if item.get("lifecycle") == "problem"]
    choices = problems or ingress
    incident_summary = _text(incident.get("summary"), 420)
    selected = next((
        item for item in choices
        if incident_summary and _text(item.get("message"), 420).casefold() ==
        incident_summary.casefold()
    ), choices[0] if choices else None)

    message = (_text(selected.get("message"), 420) if selected else "") or incident_summary
    if not message:
        message = "متن مشخصی برای آلارم ثبت نشده است."
    family = _family(message + " " + _text(selected.get("signal_type"), 120)
                     if selected else message)
    observations = []
    expected_service = _text(incident.get("service"), 120).lower().removesuffix(".service")
    for row in (brief.get("mcp_evidence") or [])[:100]:
        if not isinstance(row, dict):
            continue
        tool = _text(row.get("tool"), 70)
        finding = _text(row.get("finding"), 420)
        checks = (row.get("dependency_checks") or [])
        if not isinstance(checks, list):
            checks = []
        observed_service = _text(row.get("observed_service"), 120).lower().removesuffix(".service")
        if expected_service and observed_service and observed_service != expected_service:
            # A different named service on the same host is NOT evidence for
            # this one. Explicitly mapped aliases require separate live identity.
            continue
        if not _is_relevant(family, tool, finding, checks, message):
            continue
        # Only matching dependency endpoints are displayed as direct tests.
        matched_checks = [
            check for check in checks[:6] if isinstance(check, dict)
            and _KIND_FAMILY.get(str(check.get("kind") or "").lower()) == family
        ]
        detail = finding
        endpoints = [{
            "kind": _text(check.get("kind"), 28),
            "host": _text(check.get("host"), 120),
            "port": check.get("port") if type(check.get("port")) is int else None,
            "port_inferred": (check.get("port_inferred")
                              if type(check.get("port_inferred")) is bool else None),
            "tcp_reachable": check.get("tcp_reachable") if type(check.get("tcp_reachable")) is bool else None,
            "protocol_status": _text(check.get("protocol_status"), 65),
            "protocol_health_verified": check.get("protocol_health_verified") is True,
            "config_file": _text(check.get("config_file"), 170),
            "config_key": _text(check.get("config_key"), 100),
            "config_port_key": _text(check.get("config_port_key"), 100),
            "endpoint_source": _text(check.get("endpoint_source"), 70),
        } for check in matched_checks[:3]]
        if matched_checks:
            parts = []
            for check in matched_checks[:3]:
                kind = _text(check.get("kind"), 30)
                host = _text(check.get("host"), 110)
                port = check.get("port")
                destination = f"{kind} {host}:{port}" if type(port) is int and host else kind
                # A legacy row without port provenance is not proof that
                # the TCP test targeted the effective application port.
                transport = (
                    "پورت برنامه تأیید نشده؛ TCP روی این مقصد اعتبارسنجی ارتباط برنامه نیست"
                    if check.get("port_inferred") is not False else
                    "TCP برقرار" if check.get("tcp_reachable") is True else
                    "TCP ناموفق" if check.get("tcp_reachable") is False else
                    "TCP تأیید نشده"
                )
                protocol = _text(check.get("protocol_status"), 65)
                parts.append(f"{destination} — {transport}"
                             + (f"؛ پروتکل: {protocol}" if protocol else "؛ پروتکل تأیید نشده"))
            detail = "؛ ".join(parts)
        # The tool result is an observation, not a verified underlying RCA.
        observations.append({
            "tool": tool,
            "status": (
                "port_unverified" if matched_checks and all(
                    check.get("port_inferred") is not False
                    for check in matched_checks
                ) else _text(row.get("status"), 35) or "unknown"
            ),
            "result": detail or "نتیجه فنی تفصیلی ثبت نشده است.",
            "evidence_ref": _text(row.get("evidence_ref"), 180),
            "collected_at": _text(row.get("collected_at"), 60),
            "endpoints": endpoints,
            "llm_field_binding_status": _text(row.get("llm_field_binding_status"), 80),
            "evidence_refs": [_text(row.get("evidence_ref"), 180)] if row.get("evidence_ref") else [],
            "scope": (
                "dependency_port_not_verified" if any(
                    ep.get("port_inferred") is not False for ep in endpoints
                ) else "related_observation_not_causal_proof" if observed_service
                else "service_identity_not_recorded"
            ),
        })
        if len(observations) >= 6:
            break

    # Multiple investigation rounds can repeat the same endpoint result.
    # Collapse identical facts but retain every source reference for audit.
    collapsed: list[dict] = []
    seen: dict[tuple, dict] = {}
    for finding_row in observations:
        endpoints = finding_row.get("endpoints") or []
        key = (
            finding_row.get("tool"),
            tuple((ep.get("kind"), ep.get("host"), ep.get("port"),
                   ep.get("tcp_reachable"), ep.get("protocol_status"),
                   ep.get("port_inferred"))
                  for ep in endpoints),
            finding_row.get("result") if not endpoints else "",
            finding_row.get("scope"),
        )
        if key in seen:
            current = seen[key]
            for ref in finding_row.get("evidence_refs") or []:
                if ref and ref not in current["evidence_refs"]:
                    current["evidence_refs"].append(ref)
            continue
        seen[key] = finding_row
        collapsed.append(finding_row)
    observations = collapsed

    agent_interpretations = []
    for agent in (brief.get("agent_findings") or [])[:35]:
        if not isinstance(agent, dict) or agent.get("status") in {"failed", "skipped"}:
            continue
        candidates = agent.get("hypotheses") or []
        if not isinstance(candidates, list):
            continue
        for hypothesis in candidates[:5]:
            if not isinstance(hypothesis, dict):
                continue
            text = _text(hypothesis.get("text"), 260)
            if not text or not (
                _shares_alert_topic(message, text) if family == "other"
                else _family(text) == family
            ):
                continue
            agent_interpretations.append({
                "agent": _text(agent.get("agent"), 65),
                "hypothesis": text,
                "evidence_refs": [
                    _text(ref, 160) for ref in (hypothesis.get("evidence_refs") or [])[:4]
                    if isinstance(ref, str)
                ],
                "status": "unverified_agent_hypothesis",
            })
            if len(agent_interpretations) >= 3:
                break
        if len(agent_interpretations) >= 3:
            break

    source_ref = _text(selected.get("evidence_id"), 180) if selected else ""
    source_name = _text(selected.get("source_name"), 100) if selected else ""
    observed = len(observations)
    # Even a successful PING or a healthy systemd unit does not refute an error
    # rate in a monitoring signal or prove the application connection healthy.
    conclusion_fa = (
        "برای موضوع همین آلارم بررسی مرتبط ثبت شده، اما این نتایج به‌تنهایی "
        "درستی ادعای آلارم یا علت ریشه‌ای آن را اثبات یا رد نمی‌کنند."
        if observed else
        "برای موضوع اعلام‌شده در این آلارم هنوز تست فنی مستقل و قابل استنادی "
        "در شواهد این رخداد ثبت نشده است؛ وضعیت مشکل نامشخص است."
    )
    return {
        "status": "related_checks_recorded" if observed else "no_relevant_checks",
        "alert_message": message,
        "alert_source": source_name or _text(incident.get("context", {}).get("source")
                                             if isinstance(incident.get("context"), dict) else "", 70)
                        or "ثبت رخداد",
        "alert_type": _text(selected.get("signal_type"), 160) if selected else "",
        "alert_evidence_ref": source_ref,
        "source_basis": "received_signal" if selected else "incident_summary_fallback",
        "family": family,
        "related_checks": observations,
        "agent_interpretations": agent_interpretations,
        "assessment_fa": conclusion_fa,
        "next_check_fa": _FOLLOWUPS_FA[family],
        "root_cause_confirmed": False,
        "read_only": True,
        "authorizes_execution": False,
    }
