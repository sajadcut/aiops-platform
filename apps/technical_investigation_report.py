"""Deterministic, read-only SRE investigation built exclusively from durable evidence.

No model inference, remote execution or approval decisions occur in this module.
Absence of a sample, a successful empty query and an unavailable provider have
different semantics. All displays are redacted and evidence-attributed.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from domain.contracts.redaction import redact


DOMAINS = (
    ("systemd", "سرویس و systemd", "vm_mcp", ("service_status", "service_runtime_discovery")),
    ("journal", "لاگ سیستم‌عامل و Journal", "vm_mcp", ("service_logs", "system_logs")),
    ("elastic", "Elasticsearch / ELK", "elasticsearch", ()),
    ("resources", "CPU، RAM و Swap", "vm_mcp", ("collect_vm_metrics", "memory_diagnostics", "process_snapshot")),
    ("disk", "Disk و Filesystem", "vm_mcp", ("disk_status", "disk_forensics")),
    ("network", "Process، Network و Port", "vm_mcp", ("process_status", "port_listener_status", "tcp_check", "network_status", "dns_check", "route_check")),
    ("config", "Application Configuration", "vm_mcp", ("config_validate", "dotnet_config_syntax")),
    ("monitoring", "Prometheus و Zabbix", "monitoring", ()),
    ("cognia", "Cognia و تجربه‌های قبلی", "knowledge", ()),
)
# No raw config, secrets, full logs or unbounded tool payloads in the UI.
SCALARS = {
    "active_state", "sub_state", "result", "exit_code", "exec_main_status",
    "main_pid", "restart_count", "n_restarts", "timeout_start_usec",
    "timeout_start_sec", "service_type", "exec_start", "runtime", "entrypoint",
    "unit_file", "running", "count", "supported", "valid", "syntax_valid",
    "validated_scope", "publish_directory", "listening", "reachable",
    "target_port", "port", "cpu_usage", "memory_used_percent", "mem_available",
    "mem_available_kb", "swap_used_percent", "swap_total_kb", "swap_free_kb",
    "memory_psi", "used_percent", "free_bytes", "mount", "io_wait",
    "io_latency_ms", "oom_kills", "log_rotation", "growth_bytes",
    "status", "result_count", "detail",
}
LIST_FIELDS = {"filesystems", "inodes", "large_files", "top_processes", "processes", "files"}
SAFE_LIST_KEYS = {
    "mount", "filesystem", "use_percent", "free_bytes", "avail_bytes",
    "inodes_used_percent", "file", "path", "size_bytes", "pid", "name",
    "cpu_percent", "memory_percent", "rss_bytes", "status", "error_code",
    "line", "column", "reason",
}
COLLECTION_HINTS = {
    "systemd": "VM MCP: service_status و service_runtime_discovery را با هویت سرویس/میزبان اجرا کنید.",
    "journal": "VM MCP: service_logs، system_logs و رویدادهای Kernel/OOM را برای بازهٔ رخداد جمع‌آوری کنید.",
    "elastic": "Elastic MCP: Query مقید به سرویس، میزبان و بازهٔ رخداد و شمارش Error/Warning.",
    "resources": "VM MCP: collect_vm_metrics، memory_diagnostics و process_snapshot؛ برای روند از Prometheus استفاده کنید.",
    "disk": "VM MCP: disk_status، inode و disk_forensics؛ وضعیت Mount و logrotate را بررسی کنید.",
    "network": "VM MCP: MainPID را با process_status، port_listener_status و tcp_check تطبیق دهید.",
    "config": "VM MCP: config_validate، service_runtime_discovery و Validator اختصاصی Runtime.",
    "monitoring": "Zabbix و Prometheus: وضعیت Alert/Recovery و نمونه‌های زمان‌دار را دریافت کنید.",
    "cognia": "بازیابی Cognia را فقط برای سرویس و Runtime هم‌هویت و خطای مرتبط بررسی کنید.",
}


def _time(value: Any) -> datetime | None:
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        return parsed.astimezone(timezone.utc) if parsed.tzinfo else None
    except (TypeError, ValueError, OverflowError):
        return None


def _text(value: Any, length: int = 180) -> str:
    if value is None:
        return ""
    return str(redact(str(value)))[:length]


def _service(value: Any) -> str:
    return str(value or "").strip().lower().removesuffix(".service")


def _source(row: dict) -> str:
    return str(row.get("source") or "").lower()


def _stamp(row: dict) -> str | None:
    raw = row.get("raw_data") or {}
    if not isinstance(raw, dict):
        raw = {}
    stamp = raw.get("collected_at") or raw.get("observed_at") or raw.get("timestamp") or row.get("created_at") or row.get("timestamp")
    return str(stamp) if _time(stamp) else None


def _fact_fields(raw: dict) -> dict:
    facts = {}
    for key in sorted(SCALARS):
        value = raw.get(key)
        if isinstance(value, (str, int, float, bool)) and not isinstance(value, complex):
            facts[key] = _text(value, 170) if isinstance(value, str) else value
    if isinstance(raw.get("metrics"), dict):
        facts["metrics"] = {
            str(k)[:60]: v for k, v in list(raw["metrics"].items())[:24]
            if isinstance(v, (int, float)) and not isinstance(v, bool)
        }
    for key in LIST_FIELDS:
        if isinstance(raw.get(key), list):
            facts[key] = [
                {k: (_text(v, 110) if isinstance(v, str) else v)
                 for k, v in item.items() if k in SAFE_LIST_KEYS
                 and isinstance(v, (str, int, float, bool))}
                for item in raw[key][:12] if isinstance(item, dict)
            ]
    if isinstance(raw.get("entries"), list):
        # Journal excerpts can contain access tokens; report signatures only,
        # never expose raw lines or claim OOM unless the text explicitly says so.
        entries = [str(x) for x in raw["entries"][:150]]
        facts["journal_lines"] = len(entries)
        for name, tokens in (
            ("oom_mentions", ("out of memory", "oom-kill", "killed process")),
            ("timeout_mentions", ("timed out", "timeout", "start operation timed")),
            ("dependency_mentions", ("dependency failed", "failed to start")),
            ("error_mentions", ("error", "failed", "exception")),
        ):
            facts[name] = sum(any(token in line.lower() for token in tokens) for line in entries)
    return facts


def _state(row: dict, now: datetime) -> str:
    stamp = _time(_stamp(row))
    return "stale" if not stamp or not -60 <= (now - stamp).total_seconds() <= 900 else "fresh"


def _matches(row: dict, service: str, host: str | None) -> bool:
    raw = row.get("raw_data") or {}
    if not isinstance(raw, dict):
        return False
    identified = raw.get("service") or (raw.get("labels") or {}).get("service") if isinstance(raw.get("labels") or {}, dict) else raw.get("service")
    if identified and _service(identified) != service:
        return False
    target = raw.get("target") or raw.get("host_ip")
    return not (target and host and str(target).lower() != host.lower())


def _domain_rows(rows: list[dict], key: str, diagnostics: tuple[str, ...]) -> list[dict]:
    selected = []
    for row in rows:
        raw = row.get("raw_data") or {}
        source = _source(row)
        diagnostic = str(raw.get("diagnostic") or raw.get("tool_name") or "")
        if key == "elastic" and source == "elasticsearch":
            selected.append(row)
        elif key == "monitoring" and source in {"prometheus", "zabbix"}:
            selected.append(row)
        elif key not in {"elastic", "monitoring", "cognia"} and source == "vm_mcp" and diagnostic in diagnostics:
            selected.append(row)
    return selected


def _provider_status(rows: list[dict], status: str, now: datetime) -> str:
    if not rows:
        return "not_queried"
    if all(_state(row, now) == "stale" for row in rows):
        return "stale"
    observations = [row["raw_data"] for row in rows
                    if isinstance(row.get("raw_data"), dict)
                    and "result_count" in row["raw_data"]]
    if any(str(o.get("status")) in {"unavailable", "error"} for o in observations):
        return "query_failed" if not any(o.get("status") == "queried" for o in observations) else "partial"
    if any(o.get("status") == "skipped" for o in observations) and len(rows) == len(observations):
        return "not_applicable"
    if any(o.get("status") == "queried" and o.get("result_count") == 0 for o in observations) and len(rows) == len(observations):
        return "queried_zero_results"
    if any(o.get("status") == "queried" for o in observations):
        return "queried_with_results" if any(int(o.get("result_count") or 0) > 0 for o in observations) else "queried_zero_results"
    return "partial"


def build_technical_investigation(*, incident: dict, evidence: list[dict],
                                  knowledge: dict, now: datetime,
                                  approval: dict | None = None) -> dict:
    service = _service(incident.get("service"))
    context = incident.get("context") if isinstance(incident.get("context"), dict) else {}
    signal = context.get("trigger_signal") if isinstance(context.get("trigger_signal"), dict) else {}
    payload = signal.get("payload") if isinstance(signal.get("payload"), dict) else signal
    host = (payload.get("target_ip") or payload.get("host_ip")
            or context.get("host") or context.get("hostname"))
    # Do not silently merge observations across service/host identities.
    matching = [row for row in evidence if isinstance(row, dict) and
                isinstance(row.get("raw_data"), dict) and _matches(row, service, str(host) if host else None)]
    mismatched = len(evidence) - len(matching)
    domains = []
    confirmed = []
    by_key = {}
    for key, title, source_name, diagnostics in DOMAINS:
        domain_rows = _domain_rows(matching, key, diagnostics)
        domain_rows.sort(key=lambda row: _time(_stamp(row)) or datetime.min.replace(tzinfo=timezone.utc), reverse=True)
        latest = domain_rows[0] if domain_rows else None
        if key == "cognia":
            status = str(knowledge.get("status") or "not_queried")
            accepted = int(knowledge.get("accepted_count") or 0)
            status = "queried_with_results" if accepted else "queried_zero_results" if status in {"empty", "filtered_empty", "available"} else "query_failed" if status == "failed" else "not_queried"
        elif key in {"elastic", "monitoring"}:
            status = _provider_status(domain_rows, key, now)
        elif not domain_rows:
            status = "not_queried"
        elif all(_state(row, now) == "stale" for row in domain_rows):
            status = "stale"
        elif any(row["raw_data"].get("success") is False for row in domain_rows):
            status = "partial"
        elif key == "config" and all(row["raw_data"].get("supported") is False for row in domain_rows):
            status = "partial"
        else:
            status = "investigated"
        evidence_rows = []
        for row in domain_rows[:12]:
            raw = row["raw_data"]
            evidence_rows.append({
                "id": _text(row.get("id") or row.get("evidence_id") or row.get("reference"), 170),
                "observed_at": _stamp(row),
                "freshness": _state(row, now),
                "source": _text(row.get("source"), 50),
                "tool": _text(raw.get("diagnostic") or raw.get("tool_name") or "source_observation", 70),
                "facts": _fact_fields(raw),
            })
        technical = ""
        if key == "systemd":
            state_record = next((r for r in domain_rows if r["raw_data"].get("diagnostic") == "service_status"
                                 and r["raw_data"].get("success") is True), None)
            runtime_record = next((r for r in domain_rows if r["raw_data"].get("diagnostic") == "service_runtime_discovery"), None)
            if state_record:
                d = state_record["raw_data"]
                technical = "systemd: ActiveState={}; SubState={}; Result={}; MainPID={}; RestartCount={}".format(
                    *[d.get(k, "ثبت نشده") for k in ("active_state", "sub_state", "result", "main_pid", "restart_count")])
                if d.get("result") == "timeout":
                    technical += "؛ Timeout ثبت شده، اما مکانیسم ایجاد آن هنوز تأیید نشده است."
                if d.get("active_state") in {"failed", "inactive"}:
                    confirmed.append({"text": f"systemd توقف سرویس {service} را گزارش کرده است.",
                                      "evidence_refs": [str(state_record.get("id") or state_record.get("reference") or "")]})
            if runtime_record:
                d = runtime_record["raw_data"]
                technical += f" Runtime={_text(d.get('runtime'))}; Entrypoint={_text(d.get('entrypoint'))}; TimeoutStart={_text(d.get('timeout_start_usec'))}."
        elif key == "journal" and domain_rows:
            record = next((e for e in evidence_rows if "journal_lines" in e["facts"]), None)
            if record:
                f = record["facts"]
                technical = f"Journal: {f['journal_lines']} سطر؛ Error={f['error_mentions']}، Timeout={f['timeout_mentions']}، OOM={f['oom_mentions']}، Dependency={f['dependency_mentions']} (شمارش امضا، نه اثبات علت)."
            else:
                technical = "لاگ گردآوری شده ولی شمارش خطا در خروجی ابزار موجود نیست."
        elif key in {"elastic", "monitoring"}:
            q = [r["raw_data"] for r in domain_rows if "result_count" in r["raw_data"] and r["raw_data"].get("status") == "queried"]
            matched_count = sum(int(x.get("result_count") or 0) for x in q)
            records = [r["raw_data"] for r in domain_rows if "result_count" not in r["raw_data"]]
            errors = sum(str(x.get("level") or x.get("severity") or "").lower() in {"error", "fatal", "critical"} for x in records)
            warns = sum(str(x.get("level") or x.get("severity") or "").lower() in {"warn", "warning"} for x in records)
            technical = f"Query موفق: {len(q)}؛ Match={matched_count}؛ رکورد Error={errors}، Warning={warns}. "
            if status == "queried_zero_results":
                technical += "صفر نتیجه، سلامت سرویس را ثابت نمی‌کند."
        elif key == "config":
            validations = {r["raw_data"].get("diagnostic"): r["raw_data"] for r in domain_rows}
            generic = validations.get("config_validate") or {}
            special = validations.get("dotnet_config_syntax") or {}
            technical = ("Generic Validator: " + ("Unsupported" if generic.get("supported") is False else
                         "Valid" if generic.get("valid") is True else "Invalid" if generic.get("valid") is False else "بررسی نشده") +
                         "؛ .NET JSON Syntax: " + ("Valid" if special.get("syntax_valid") is True else
                         "Invalid" if special.get("syntax_valid") is False else "بررسی نشده") +
                         "؛ Syntax Valid به معنی Semantic Valid یا Runtime Healthy نیست.")
        elif key == "network":
            proc = next((r["raw_data"] for r in domain_rows if r["raw_data"].get("diagnostic") == "process_status"), {})
            technical = ("Process running=" + str(proc.get("running", "ثبت نشده")) +
                         "؛ برای .NET، نام process به‌تنهایی کافی نیست؛ MainPID و dotnet باید تطبیق داده شوند.")
        elif domain_rows:
            latest_facts = evidence_rows[0]["facts"]
            technical = "؛ ".join(f"{k}={v}" for k, v in latest_facts.items()
                                 if isinstance(v, (int, float, str, bool)))[:470]
        elif key == "cognia":
            technical = f"اسناد مرتبط: {int(knowledge.get('accepted_count') or 0)}؛ اسناد ردشده از نظر ارتباط: {int(knowledge.get('rejected_count') or 0)}."
        if not technical:
            technical = "برای این حوزه نتیجهٔ فنی قابل انتساب ثبت نشده است."
        observed = _stamp(latest) if latest else None
        missing_reason = ("شواهدی با هویت سرویس/میزبان و منبع معتبر برای این حوزه ثبت نشده است." if not domain_rows
                          else "شواهد موجود قدیمی هستند و وضعیت فعلی را تأیید نمی‌کنند." if status == "stale"
                          else "منبع ناموفق یا فاقد دادهٔ کافی بوده است." if status in {"partial", "query_failed", "not_applicable"}
                          else None)
        domain = {
            "key": key, "title": title, "status": status, "technical_result": _text(technical, 620),
            "importance": "بحرانی" if key == "systemd" else "بالا" if key in {"journal", "elastic", "disk", "network"} else "متوسط",
            "observed_at": observed, "source": source_name, "evidence": evidence_rows,
            "missing_reason": missing_reason,
            "collection_hint": COLLECTION_HINTS[key],
        }
        domains.append(domain)
        by_key[key] = domain
    sys = next((e for e in by_key["systemd"]["evidence"] if e["tool"] == "service_status"), None)
    sysfacts = sys["facts"] if sys else {}
    hypotheses = []
    if sysfacts.get("result") == "timeout":
        hypotheses.append({
            "title": "تأخیر Startup یا Dependency خارجی",
            "supporting": [sys["id"]], "opposing": [],
            "check": "Journal زمان Startup را با خطاهای برنامه و دسترسی Dependencyها تطبیق دهید.",
            "confidence": None, "kind": "فرضیه، نه RCA تأییدشده",
        })
    if by_key["disk"]["status"] == "investigated":
        hypotheses.append({
            "title": "فشار ظرفیت Disk یا I/O (صرفاً فرضیه بررسی)",
            "supporting": [], "opposing": [],
            "check": "Mount مرتبط، Inode، I/O Latency و زمان خطا را با Startup تطبیق دهید.",
            "confidence": None, "kind": "علت احتمالی تأیید نشده",
        })
    unknowns = [{"domain": d["title"], "reason": d["missing_reason"],
                 "next_check": d["collection_hint"]}
                for d in domains if d["missing_reason"]]
    if mismatched:
        unknowns.append({"domain": "هویت Evidence", "reason": f"{mismatched} رکورد نامنطبق از گزارش حذف شد.",
                         "next_check": "Service و Host را از Signal و VM MCP تطبیق دهید."})
    checks = [d for d in domains if d["status"] in {"not_queried", "query_failed", "partial", "stale"}]
    actions = {
        "read_only": [
            {"title": d["title"], "goal": d["missing_reason"] or "تأیید نتیجه و ارتباط زمانی",
             "tool": d["source"], "prerequisite": "دسترسی Read-only مجاز به منبع با هویت تأییدشده",
             "status": "proposed_not_executed", "expected": d["collection_hint"],
             "if_positive": "نتیجه را به RCA همراه Evidence ID اضافه کنید.",
             "if_negative": "شکاف را ثبت و مسیر جمع‌آوری جایگزین مجاز را بررسی کنید.",
             "approval_required": False}
            for d in checks[:5]
        ],
        "conditional": [{
            "title": "ارزیابی Start/Restart تنها پس از بررسی",
            "goal": "بازگرداندن سرویس پس از کاهش ریسک و تشخیص شرایط",
            "tool": "مسیر Governed Action موجود",
            "prerequisite": "تأیید وضعیت فعلی، سلامت کانفیگ، وابستگی‌ها و Approval معتبر",
            "status": "proposed_not_executed",
            "expected": "اجرای جداگانه و Verification مستقل؛ این گزارش مجوز اجرا نیست.",
            "if_positive": "سلامت برنامه و مانیتورینگ را مستقل تأیید کنید.",
            "if_negative": "بدون تکرار کورکورانه، به Incident Commander ارجاع دهید.",
            "approval_required": True,
        }],
        "prohibited": ["Restart تکراری بدون تشخیص علت و Approval",
                       "Kill پردازش بدون تطبیق PID و مجوز",
                       "حذف syslog یا daemon.log صرفاً به علت حجم بالا",
                       "افزایش Timeout یا Resources بدون شاهد و Change Control"],
    }
    header = [
        f"سرویس {service or 'نامشخص'} روی میزبان {_text(host) or 'تأییدنشده'}؛ شروع رخداد: {_text(incident.get('started_at'), 55) or 'ثبت نشده'}.",
        by_key["systemd"]["technical_result"],
        "ELK: " + by_key["elastic"]["technical_result"],
        "Journal: " + by_key["journal"]["technical_result"],
        "CPU/RAM: " + by_key["resources"]["technical_result"],
        "Disk: " + by_key["disk"]["technical_result"],
        "اقدام بعدی: " + (actions["read_only"][0]["expected"] if actions["read_only"] else "بررسی شرایط قبل از هر تغییر؛ Approval مستقل الزامی است."),
    ]
    return redact({
        "version": "technical-investigation.v1", "read_only": True,
        "service": service, "host": _text(host) or None,
        "executive_lines": header, "domains": domains,
        "rca": {"confirmed_facts": confirmed, "likely_hypotheses": hypotheses,
                "ruled_out": [], "remaining_unknowns": unknowns,
                "cause_confirmed": False,
                "note": "Timeout و هم‌زمانی شواهد، علت ریشه‌ای یا مقصر بودن Process را اثبات نمی‌کنند."},
        "actions": actions,
        "identity_mismatch_count": mismatched,
        "approval_status": str((approval or {}).get("status") or "not_recorded"),
    })
