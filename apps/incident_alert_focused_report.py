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


def _is_relevant(family: str, tool: str, finding: str, checks: list[dict]) -> bool:
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
        # Prefer only diagnostics mentioning meaningful alert-specific tokens
        # over unrelated host telemetry.
        return False
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
    for row in (brief.get("mcp_evidence") or [])[:100]:
        if not isinstance(row, dict):
            continue
        tool = _text(row.get("tool"), 70)
        finding = _text(row.get("finding"), 420)
        checks = (row.get("dependency_checks") or [])
        if not isinstance(checks, list):
            checks = []
        if not _is_relevant(family, tool, finding, checks):
            continue
        # Only matching dependency endpoints are displayed as direct tests.
        matched_checks = [
            check for check in checks[:6] if isinstance(check, dict)
            and _KIND_FAMILY.get(str(check.get("kind") or "").lower()) == family
        ]
        detail = finding
        if matched_checks:
            parts = []
            for check in matched_checks[:3]:
                kind = _text(check.get("kind"), 30)
                host = _text(check.get("host"), 110)
                port = check.get("port")
                destination = f"{kind} {host}:{port}" if type(port) is int and host else kind
                transport = ("TCP برقرار" if check.get("tcp_reachable") is True
                             else "TCP ناموفق" if check.get("tcp_reachable") is False
                             else "TCP تأیید نشده")
                protocol = _text(check.get("protocol_status"), 65)
                parts.append(f"{destination} — {transport}"
                             + (f"؛ پروتکل: {protocol}" if protocol else "؛ پروتکل تأیید نشده"))
            detail = "؛ ".join(parts)
        # The tool result is an observation, not a verified underlying RCA.
        observations.append({
            "tool": tool,
            "status": _text(row.get("status"), 35) or "unknown",
            "result": detail or "نتیجه فنی تفصیلی ثبت نشده است.",
            "evidence_ref": _text(row.get("evidence_ref"), 180),
            "collected_at": _text(row.get("collected_at"), 60),
            "scope": "related_observation_not_causal_proof",
        })
        if len(observations) >= 6:
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
        "assessment_fa": conclusion_fa,
        "next_check_fa": _FOLLOWUPS_FA[family],
        "root_cause_confirmed": False,
        "read_only": True,
        "authorizes_execution": False,
    }
