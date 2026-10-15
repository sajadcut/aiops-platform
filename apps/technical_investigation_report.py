"""Deterministic, read-only SRE investigation built exclusively from durable evidence.

No model inference, remote execution or approval decisions occur in this module.
Absence of a sample, a successful empty query and an unavailable provider have
different semantics. All displays are redacted and evidence-attributed.
"""
from __future__ import annotations

from datetime import datetime, timezone
import re
from typing import Any

from domain.contracts.redaction import redact
from integrations.vm.runtime_discovery import safe_absolute_path
from integrations.vm.dotnet_local_validator import _NAME as SAFE_DOTNET_JSON_NAME


DOMAINS = (
    ("systemd", "سرویس و systemd", "vm_mcp", ("service_status", "service_runtime_discovery")),
    ("journal", "لاگ سیستم‌عامل و Journal", "vm_mcp", ("service_logs", "system_logs")),
    ("elastic", "Elasticsearch / ELK", "elasticsearch", ()),
    ("resources", "CPU، RAM و Swap", "vm_mcp", ("collect_vm_metrics", "memory_diagnostics", "process_snapshot")),
    ("disk", "Disk و Filesystem", "vm_mcp", ("disk_status", "disk_forensics")),
    ("network", "Process، Network و Port", "vm_mcp", ("process_status", "port_listener_status", "tcp_check", "network_status", "dns_check", "route_check")),
    ("config", "Application Configuration", "vm_mcp", ("config_validate", "dotnet_config_syntax",
        "nginx_config_review", "nginx_config_inspect", "service_config_discovery", "service_config_review")),
    ("monitoring", "Prometheus و Zabbix", "monitoring", ()),
    ("cognia", "Cognia و تجربه‌های قبلی", "knowledge", ()),
)
# No raw config, secrets, full logs or unbounded tool payloads in the UI.
SCALARS = {
    "active_state", "sub_state", "result", "exit_code", "exec_main_status",
    "main_pid", "restart_count", "n_restarts", "timeout_start_usec",
    "timeout_start_sec", "service_type", "runtime", "entrypoint",
    "unit_file", "running", "count", "supported", "valid", "syntax_valid",
    "validated_scope", "publish_directory", "listening", "reachable",
    "target_port", "port", "cpu_usage", "memory_used_percent", "mem_available",
    "mem_available_kb", "swap_used_percent", "swap_total_kb", "swap_free_kb",
    "memory_psi", "used_percent", "free_bytes", "mount", "io_wait",
    "total_mb", "available_mb", "cache_reclaimable_mb", "swap_used_mb",
    "swap_total_mb", "psi_memory_some_avg10", "snapshot_only",
    "reason_cannot_be_proven_from_single_snapshot", "query_service",
    "query_since", "query_until", "host_filter_applied",
    "io_latency_ms", "oom_kills", "log_rotation", "growth_bytes",
    "status", "result_count", "detail", "name", "value",
}
LIST_FIELDS = {"filesystems", "inodes", "large_files", "top_processes", "processes", "files"}
SAFE_LIST_KEYS = {
    "mount", "filesystem", "use_percent", "free_bytes", "avail_bytes",
    "available", "used", "blocks", "ppid", "command", "rss_mb",
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
    "config": "VM MCP: نتیجهٔ Validator و فایل تأییدشدهٔ همین سرویس/Runtime را بررسی کنید.",
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
    # A disk-forensics observation already contains the largest files.
    # Persist only bounded path/size facts; never forward log contents or imply
    # a file is safe to remove or that its writer caused the incident.
    if raw.get("diagnostic") == "disk_forensics" and isinstance(raw.get("mounts"), list):
        largest = []
        for mount in raw["mounts"][:12]:
            if not isinstance(mount, dict) or mount.get("mount") != "/var/log":
                continue
            for item in mount.get("files", [])[:25]:
                if not isinstance(item, dict):
                    continue
                path = item.get("path")
                size = item.get("size_bytes")
                if (isinstance(path, str) and path.startswith("/var/log/")
                        and isinstance(size, int) and size >= 0):
                    largest.append({"path": _text(path, 160), "size_bytes": size})
        if largest:
            facts["largest_log_files"] = sorted(
                largest, key=lambda item: item["size_bytes"], reverse=True
            )[:6]
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
    labels = raw.get("labels") if isinstance(raw.get("labels"), dict) else {}
    # Check every declared identity: same host does not imply same service.
    for declared in (raw.get("service"), labels.get("service"),
                     raw.get("query_service"), raw.get("searched_service")):
        if declared and _service(declared) != service:
            return False
    diagnostic = str(raw.get("diagnostic") or raw.get("tool_name") or "")
    if _source(row) == "vm_mcp" and diagnostic in {
        "service_status", "service_logs", "config_validate", "process_status",
        "service_runtime_discovery", "service_config_discovery",
        "service_config_review", "nginx_config_review",
        "nginx_config_inspect", "dotnet_config_syntax",
    } and not raw.get("service"):
        # Do not attribute an unbound service probe to a shared VM's unit.
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



def _latest_metric(rows: list[dict], name: str) -> tuple[float | None, dict | None]:
    """Collector emits {name, value} rows, rather than a metrics dict."""
    for row in rows:  # already newest-first
        raw = row["raw_data"]
        if raw.get("diagnostic") != "collect_vm_metrics":
            continue
        value = (raw.get("value") if raw.get("name") == name else
                 (raw.get("metrics") or {}).get(name) if isinstance(raw.get("metrics"), dict) else None)
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            number = float(value)
            if number == number and 0 <= number <= 100:
                return round(number, 2), row
    return None, None


def _best_diagnostic(rows: list[dict], name: str) -> dict:
    return next((r["raw_data"] for r in rows
                 if r["raw_data"].get("diagnostic") == name
                 and r["raw_data"].get("success") is True), {})


def _sample(value: Any, suffix: str = "") -> str:
    return (f"{value:g}" if isinstance(value, float) else str(value)) + suffix if value is not None else "ثبت نشده"


def _journal_counts(rows: list[dict]) -> dict:
    entries = []
    for row in rows:
        raw = row["raw_data"]
        if raw.get("diagnostic") not in {"service_logs", "system_logs"}:
            continue
        collected = raw.get("entries")
        if not isinstance(collected, list):
            collected = raw.get("logs")
        if not isinstance(collected, list):
            continue
        entries.extend(str(x).lower() for x in collected[:150])
    signatures = {
        "oom": ("out of memory", "oom-kill", "killed process"),
        "timeout": ("timed out", "timeout", "start operation timed"),
        "dependency": ("dependency failed", "failed to start"),
        "exception": ("exception", "traceback", "segmentation fault"),
        "permission": ("permission denied", "access denied"),
        "disk_full": ("no space left on device", "enospc"),
    }
    return {"lines": len(entries), "signatures": {
        label: sum(any(token in line for token in patterns) for line in entries)
        for label, patterns in signatures.items()
    }}


def _stop_origin_assessment(rows: list[dict], service: str, systemd: dict | None) -> dict | None:
    """Distinguish confirmed termination from unproven *origin* of a stop job.

    SIGKILL and Result=timeout are compatible with a stop timeout but cannot
    identify a human actor. A journal "Stopping" event alone cannot identify
    one either: automation and dependencies also issue stop jobs. Never expose
    raw journal lines or attach an identity without a matching audit command.
    """
    if not systemd:
        return None
    raw = systemd.get("raw_data") or {}
    if raw.get("active_state") not in {"failed", "inactive"} or raw.get("result") != "timeout":
        return None
    sid = str(systemd.get("id") or systemd.get("reference") or "")
    refs = [sid] if sid else []
    command_refs, stop_refs, stop_timeout_refs, start_timeout_refs = [], [], [], []
    unit = re.escape(service)
    command = re.compile(
        rf"\bCOMMAND\s*=\s*(?:/[a-zA-Z0-9_./-]+/)?systemctl\s+"
        rf"(?:--[a-zA-Z-]+\s+)*stop\s+{unit}(?:\.service)?(?:\s|$)",
        re.IGNORECASE
    )
    stopping = re.compile(rf"\bStopping\s+{unit}(?:\.service)?(?:\b|\s)", re.IGNORECASE)
    for row in rows:
        data = row.get("raw_data") or {}
        if (row.get("source") != "vm_mcp"
                or data.get("diagnostic") not in {"service_logs", "system_logs"}):
            continue
        lines = data.get("entries")
        if not isinstance(lines, list):
            lines = data.get("logs")
        if not isinstance(lines, list):
            continue
        evidence_id = str(row.get("id") or row.get("reference") or "")
        for entry in lines[:150]:
            if not isinstance(entry, str):
                continue
            lower = entry.lower()
            if command.search(entry):
                command_refs.append(evidence_id)
            if stopping.search(entry):
                stop_refs.append(evidence_id)
            if "stop operation timed out" in lower:
                stop_timeout_refs.append(evidence_id)
            if "start operation timed out" in lower:
                start_timeout_refs.append(evidence_id)
    cmd = bool(command_refs)
    observed_stop = bool(stop_refs or stop_timeout_refs)
    # Do not promote a command logged after the failure or from another
    # service into an attributed cause. This is a signal for correlation.
    status = ("audit_stop_command_observed" if cmd
              else "stop_job_observed" if observed_stop
              else "possible_unverified")
    note = (
        "دستور systemctl stop در لاگ Audit/Sudo ثبت شده، اما تطبیق زمان آن با پایان "
        "پردازش و هویت اجراکننده هنوز لازم است."
        if cmd else
        "رویداد Stop در Journal دیده شده، اما دستی یا خودکار بودن آن معلوم نیست."
        if observed_stop else
        "Timeout و خاتمهٔ پردازش با توقف دستی یا خودکارِ طول‌کشیده سازگارند؛ "
        "اما هیچ دستور Stop یا رویداد آغاز توقف به‌صورت قابل‌استناد مشاهده نشده است."
    )
    if start_timeout_refs:
        note += " همچنین نشانه‌ای از Timeout شروع سرویس ثبت شده و باید تفکیک شود."
    indicators = [
        f"Systemd Result={raw.get('result')}",
        f"ExecMainStatus={raw.get('exec_main_status') if raw.get('exec_main_status') is not None else 'unknown'}",
        f"TimeoutStop={_text(raw.get('timeout_stop_usec'), 40) or 'unknown'}",
    ]
    status_text = str(raw.get("systemctl_status") or "")[:2000]
    duration = re.search(r"(?m)^\s*Duration:\s*([0-9a-zA-Z .]+)$", status_text)
    if duration:
        indicators.append("Previous runtime duration=" + _text(duration.group(1).strip(), 45))
    if "signal=KILL" in status_text:
        indicators.append("Termination signal=SIGKILL")
    evidence_refs = list(dict.fromkeys(refs + command_refs + stop_refs +
                                       stop_timeout_refs + start_timeout_refs))
    return {
        "status": status, "note_fa": note,
        "indicators": indicators,
        "evidence_refs": evidence_refs,
        "next_check_fa": (
            "Journal بازهٔ شروع Stop و auditd/sudo برای systemctl stop/restart، "
            "همراه زمان اجرای دستور و تطبیق آن با FailedSince را بررسی کنید."
        ),
        "manual_stop_proven": False,
        "execution_origin_verified": False,
        "audit_command_seen": cmd,
        "stop_job_seen": observed_stop,
        "start_timeout_seen": bool(start_timeout_refs),
    }


def _bounded_files(rows: list[dict]) -> list[dict]:
    files = []
    for row in rows:
        raw = row["raw_data"]
        if raw.get("diagnostic") != "disk_forensics" or raw.get("success") is not True:
            continue
        for mount in (raw.get("mounts") or [])[:4]:
            if not isinstance(mount, dict):
                continue
            for item in (mount.get("files") or [])[:12]:
                if not isinstance(item, dict):
                    continue
                size, path = item.get("size_bytes"), item.get("path")
                if not isinstance(size, (int, float)) or not isinstance(path, str):
                    continue
                files.append({
                    "path": _text(path, 180),
                    "size_mb": round(size / (1024 ** 2), 1),
                    "growth_confirmed": item.get("growth_confirmed") is True,
                    "growth_measured": item.get("growth_measured") is True,
                    "evidence_ref": str(row.get("id") or row.get("reference") or ""),
                })
    return sorted(files, key=lambda x: -x["size_mb"])[:6]


def build_technical_investigation(*, incident: dict, evidence: list[dict],
                                  knowledge: dict, now: datetime,
                                  approval: dict | None = None) -> dict:
    service = _service(incident.get("service"))
    context = incident.get("context") if isinstance(incident.get("context"), dict) else {}
    signal = context.get("trigger_signal") if isinstance(context.get("trigger_signal"), dict) else {}
    payload = signal.get("payload") if isinstance(signal.get("payload"), dict) else signal
    host = (payload.get("target_ip") or payload.get("host_ip")
            or context.get("host") or context.get("hostname"))
    if not host:
        # A single tool-attributed host is safer than inventing a host name.
        vm_hosts = {str(row["raw_data"]["target"]) for row in evidence
                    if isinstance(row, dict) and row.get("source") == "vm_mcp"
                    and isinstance(row.get("raw_data"), dict)
                    and row["raw_data"].get("target")
                    and _service(row["raw_data"].get("service")) == service}
        host = next(iter(vm_hosts)) if len(vm_hosts) == 1 else None
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
            runtime_record = next((r for r in domain_rows
                                   if r["raw_data"].get("diagnostic") == "service_runtime_discovery"
                                   and r["raw_data"].get("success") is True), None)
            if state_record:
                d = state_record["raw_data"]
                technical = ("systemd: ActiveState={}; SubState={}; Result={}; "
                             "MainPID={}; ExecMainStatus={}; RestartCount={}").format(
                    *[d.get(k, "ثبت نشده") for k in (
                        "active_state", "sub_state", "result", "main_pid",
                        "exec_main_status", "restart_count"
                    )])
                if d.get("result") == "timeout":
                    technical += "؛ Timeout ثبت شده، اما مکانیسم ایجاد آن هنوز تأیید نشده است."
                if d.get("active_state") in {"failed", "inactive"} and _state(state_record, now) == "fresh":
                    confirmed.append({"text": f"systemd توقف سرویس {service} را گزارش کرده است.",
                                      "evidence_refs": [str(state_record.get("id") or state_record.get("reference") or "")]})
            if runtime_record:
                d = runtime_record["raw_data"]
                technical += (
                    f" Runtime={_text(d.get('runtime'))}; "
                    f"Entrypoint={_text(d.get('entrypoint'))}; "
                    f"Type={_text(d.get('service_type')) or 'ثبت نشده'}; "
                    f"TimeoutStart={_text(d.get('timeout_start_usec')) or 'ثبت نشده'}."
                )
        elif key == "journal" and domain_rows:
            stats = _journal_counts(domain_rows)
            sig = stats["signatures"]
            if stats["lines"]:
                technical = (f"Journal lines={stats['lines']}؛ "
                             f"Timeout={sig['timeout']}؛ OOM={sig['oom']}؛ ENOSPC={sig['disk_full']}؛ "
                             f"Dependency={sig['dependency']}؛ "
                             f"Exception={sig['exception']}؛ Permission={sig['permission']}. "
                             "شمارش الگوها در لاگ محدود؛ این شمارش اثبات علت نیست.")
            else:
                technical = ("Journal ثبت شده اما خط قابل‌تحلیل در Evidence موجود نیست؛ "
                             "صفر خط به معنی سالم بودن سرویس نیست.")
        elif key in {"elastic", "monitoring"}:
            observations = [r["raw_data"] for r in domain_rows if "result_count" in r["raw_data"]]
            succeeded = [o for o in observations if o.get("status") == "queried"]
            failed_sources = [o for o in observations if o.get("status") in {"error", "unavailable", "skipped"}]
            records = [r for r in domain_rows if "result_count" not in r["raw_data"]]
            matched_count = sum(int(o.get("result_count") or 0) for o in succeeded)
            errors = sum(str(r["raw_data"].get("level") or r["raw_data"].get("severity") or "").lower()
                         in {"error", "fatal", "critical"} for r in records)
            warns = sum(str(r["raw_data"].get("level") or r["raw_data"].get("severity") or "").lower()
                        in {"warn", "warning"} for r in records)
            if succeeded:
                technical = (f"Query اجراشده={len(succeeded)}؛ Match={matched_count}؛ "
                             f"Error={errors}؛ Warning={warns}.")
            elif failed_sources:
                codes = sorted({_text(o.get("status"), 20) for o in failed_sources})
                technical = ("هیچ Query موفقی تأیید نشده؛ وضعیت منبع: " +
                             ", ".join(codes) + "؛ تعداد نتیجه قابل استناد نیست.")
            elif records:
                technical = (f"{len(records)} رکورد ثبت شده؛ بدون مشاهدهٔ پاسخ Query، "
                             "موفقیت جست‌وجو تأیید نیست.")
            else:
                technical = "هیچ Query یا نتیجهٔ قابل انتساب ثبت نشده است."
            if key == "elastic" and succeeded:
                scope = succeeded[0]
                technical += (f" Query Service={_text(scope.get('query_service') or service)}"
                              f"؛ Since={_text(scope.get('query_since'), 45) or 'ثبت نشده'}"
                              f"؛ Until={_text(scope.get('query_until'), 45) or 'ثبت نشده'}"
                              f"؛ Host filter={'applied' if scope.get('host_filter_applied') is True else 'not_verified'}.")
                if scope.get("host_filter_applied") is not True:
                    technical += " Query فقط به سرویس مقید بوده و انتساب خطا به این VM مستقلاً تأیید نشده است."
            if failed_sources and succeeded:
                technical += " بخشی از استعلام‌ها ناموفق یا غیرقابل‌دسترس بوده‌اند."
            if status == "queried_zero_results":
                technical += " صفر نتیجه، سلامت سرویس را ثابت نمی‌کند."
        elif key == "config":
            generic = _best_diagnostic(domain_rows, "config_validate")
            special = _best_diagnostic(domain_rows, "dotnet_config_syntax")
            nginx_review = _best_diagnostic(domain_rows, "nginx_config_review")
            nginx_inspect = _best_diagnostic(domain_rows, "nginx_config_inspect")
            general_review = _best_diagnostic(domain_rows, "service_config_review")
            discovery = _best_diagnostic(domain_rows, "service_config_discovery")
            runtime = _best_diagnostic(
                _domain_rows(matching, "systemd", ("service_runtime_discovery",)),
                "service_runtime_discovery",
            )
            if generic:
                validator_status = (
                    "Unsupported" if generic.get("supported") is False else
                    "Valid" if generic.get("valid") is True else
                    "Invalid" if generic.get("valid") is False else "نامشخص"
                )
                technical = "Validator سرویس: " + validator_status
                if generic.get("config_file"):
                    technical += "؛ File=" + _text(generic["config_file"], 170)
                if type(generic.get("error_line")) is int:
                    technical += "؛ Line=" + str(generic["error_line"])
                if generic.get("valid") is False and generic.get("syntax_error"):
                    technical += "؛ خطا=" + _text(generic["syntax_error"], 140)
            else:
                technical = "Validator عمومی برای این سرویس ثبت نشده است"
            if service == "nginx":
                # Never render .NET/JSON diagnostics for an Nginx incident.
                if nginx_review:
                    technical += "؛ بازبینی Nginx=" + _text(nginx_review.get("status"), 40)
                    if nginx_review.get("config_file") and not generic.get("config_file"):
                        technical += "؛ File=" + _text(nginx_review["config_file"], 170)
                    if type(nginx_review.get("error_line")) is int and type(generic.get("error_line")) is not int:
                        technical += "؛ Line=" + str(nginx_review["error_line"])
                    if nginx_review.get("status") == "candidate_proposed":
                        technical += "؛ پیشنهاد اصلاح صرفاً پیش‌نمایش است"
                    technical += "؛ وضعیت اعتبارسنجی پیشنهاد=" + _text(
                        nginx_review.get("validation_status") or "UNVERIFIED", 35
                    )
                if nginx_inspect:
                    technical += "؛ بررسی ساختار فایل‌ها=" + _text(
                        nginx_inspect.get("status"), 35
                    )
                technical += "؛ اصلاح روی سرور یا رفع خرابی تأیید نشده است."
            elif special.get("supported") is True and (
                str(runtime.get("runtime") or "").lower() == "dotnet"
                or str(runtime.get("entrypoint") or "").lower().endswith(".dll")
            ):
                files = special.get("files") if isinstance(special.get("files"), list) else []
                directory = safe_absolute_path(special.get("publish_directory"))
                checked = []
                for file_row in files[:12]:
                    if not isinstance(file_row, dict):
                        continue
                    name = str(file_row.get("file") or "")
                    if not SAFE_DOTNET_JSON_NAME.fullmatch(name):
                        continue
                    path = safe_absolute_path(directory + "/" + name) if directory else None
                    checked.append(_text(path or name, 170) + ": " +
                                   _text(file_row.get("status"), 45))
                verified_json = (
                    special.get("syntax_valid") is True and bool(checked)
                    and all(isinstance(f, dict) and f.get("status") == "valid_json_syntax"
                            for f in files)
                )
                technical += (
                    "؛ .NET JSON Syntax: " +
                    ("Valid" if verified_json else
                     "Invalid" if special.get("syntax_valid") is False else "تأیید نشده") +
                    (f"؛ Checked files={'; '.join(checked[:12])}" if checked else
                     "؛ نام فایل JSON بررسی‌شده ثبت نشده است") +
                    "؛ Syntax Valid به معنی سلامت Runtime یا Dependency نیست."
                )
            else:
                if general_review:
                    technical += "؛ بازبینی فایل=" + _text(
                        general_review.get("status") or
                        general_review.get("validation_status") or "نامشخص", 55
                    )
                    if general_review.get("config_file"):
                        technical += "؛ File=" + _text(general_review["config_file"], 160)
                if discovery:
                    technical += "؛ کشف مسیر فایل=" + _text(
                        discovery.get("status") or "ثبت‌شده", 50
                    )
                technical += "؛ سلامت Runtime از این بررسی اثبات نمی‌شود."
        elif key == "network":
            proc = _best_diagnostic(domain_rows, "process_status")
            listener = _best_diagnostic(domain_rows, "port_listener_status")
            tcp = _best_diagnostic(domain_rows, "tcp_check")
            service_state = next((r["raw_data"] for r in matching
                                  if r["raw_data"].get("diagnostic") == "service_status"
                                  and r["raw_data"].get("success") is True), {})
            runtime = _best_diagnostic(_domain_rows(matching, "systemd",
                                                        ("service_runtime_discovery",)),
                                       "service_runtime_discovery")
            main_pid = service_state.get("main_pid")
            technical = (
                f"systemd MainPID={_sample(main_pid)}؛ "
                f"process_status name match={_sample(proc.get('running'))}؛ "
                f"Listener={_sample(listener.get('listening'))}؛ "
                f"TCP reachable={_sample(tcp.get('reachable'))}؛ "
                f"Runtime={_sample(runtime.get('runtime'))}."
            )
            if proc.get("running") is False:
                technical += (
                    f" هشدار: جست‌وجوی فرآیند با نام «{_text(service, 70)}» "
                    "ممکن است Runtime با نام متفاوت را پیدا نکند؛ عدم تطبیق نام، "
                    "اثبات توقف سرویس نیست. MainPID، cgroup و Listener را جدا بررسی کنید."
                )
            if (str(runtime.get("runtime") or "").lower() == "dotnet"
                    or str(runtime.get("entrypoint") or "").lower().endswith(".dll")):
                technical += " Runtime واقعی .NET شناسایی شده؛ نام فرآیند لزوماً نام Unit نیست."
            if not listener and not tcp:
                technical += " پورت یا TCP هدف در شواهد ثبت نشده است."
        elif key == "resources" and domain_rows:
            memory = _best_diagnostic(domain_rows, "memory_diagnostics")
            cpu, cpu_row = _latest_metric(domain_rows, "cpu_usage")
            ram_pct, ram_row = _latest_metric(domain_rows, "memory_usage")
            swap_pct, swap_row = _latest_metric(domain_rows, "swap_usage")
            io_wait, io_row = _latest_metric(domain_rows, "io_wait")
            ram = memory.get("used_percent")
            ram = ram if ram is not None else ram_pct
            technical = (f"CPU={_sample(cpu, '%')}؛ "
                         f"RAM Used={_sample(ram, '%')}؛ "
                         f"MemAvailable={_sample(memory.get('available_mb'), ' MB')}؛ "
                         f"Cache reclaimable={_sample(memory.get('cache_reclaimable_mb'), ' MB')}؛ "
                         f"Swap Used={_sample(memory.get('swap_used_mb'), ' MB')}؛ "
                         f"Swap Usage={_sample(swap_pct, '%')}؛ "
                         f"PSI avg10={_sample(memory.get('psi_memory_some_avg10'), '%')}؛ "
                         f"IO Wait={_sample(io_wait, '%')}؛ "
                         "این‌ها نمونه‌های لحظه‌ای هستند؛ بدون Time Series، علت خرابی سرویس را اثبات نمی‌کنند.")
            if not memory and ram_pct is not None:
                technical += " MemAvailable، Cache و PSI در Snapshot ثبت نشده‌اند."
        elif key == "disk" and domain_rows:
            disk = _best_diagnostic(domain_rows, "disk_status")
            mounts = disk.get("filesystems") if isinstance(disk.get("filesystems"), list) else []
            inodes = disk.get("inodes") if isinstance(disk.get("inodes"), list) else []
            # Surface the fullest mount first. The VM can report /var/log
            # after seven low-use pseudo-filesystems; position-based slicing
            # previously hid an actual 100% utilization warning.
            mount_rows = [m for m in mounts if isinstance(m, dict)]
            def mount_usage(row):
                raw = str(row.get("use_percent") or "").removesuffix("%")
                return int(raw) if raw.isdigit() else -1
            snippets = [
                f"{_text(m.get('mount'), 60)}: used={_text(m.get('use_percent'), 10) or 'ثبت نشده'}؛ "
                f"free={_text(m.get('available'), 35) or 'ثبت نشده'} bytes"
                for m in sorted(mount_rows, key=mount_usage, reverse=True)[:7]
            ]
            files = _bounded_files(domain_rows)
            file_text = "; ".join(
                f"{item['path']}={item['size_mb']} MB"
                + (" (رشد مشاهده شد)" if item["growth_confirmed"] else
                   " (رشد مشاهده نشد)" if item["growth_measured"] else " (رشد سنجیده نشد)")
                for item in files[:4]
            )
            technical = ("Mounts: " + ("؛ ".join(snippets) if snippets else "ثبت نشده") +
                         f"؛ Inode samples={len(inodes)}." +
                         (f" Files: {file_text}." if file_text else
                          " فایل‌های حجیم در شواهد این رخداد ثبت نشده‌اند.") +
                         " ظرفیت یا حجم لاگ به‌تنهایی علت خرابی سرویس نیست؛ حذف فایل مجاز نیست.")
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
    state_record = next(
        (row for row in matching
         if row.get("source") == "vm_mcp"
         and row["raw_data"].get("diagnostic") == "service_status"
         and row["raw_data"].get("success") is True),
        None,
    )
    stop_origin = _stop_origin_assessment(matching, service, state_record)
    hypotheses = []
    if stop_origin:
        hypotheses.append({
            "title": "Stop/Restart دستی یا خودکار؛ عامل آغاز هنوز اثبات نشده",
            "supporting": stop_origin["evidence_refs"], "opposing": [],
            "check": stop_origin["next_check_fa"],
            "confidence": None, "kind": "فرضیهٔ مستقل؛ Stop و SIGKILL به‌تنهایی اثبات دستور انسانی نیستند",
        })
    startup_timeout_plausible = not (stop_origin and
        any(item.startswith("Previous runtime duration=") for item in stop_origin["indicators"])
        and not stop_origin["start_timeout_seen"])
    if sysfacts.get("result") == "timeout" and startup_timeout_plausible:
        hypotheses.append({
            "title": "تأخیر Startup یا Dependency خارجی",
            "supporting": [sys["id"]], "opposing": [],
            "check": "Journal زمان Startup را با خطاهای برنامه و دسترسی Dependencyها تطبیق دهید.",
            "confidence": None, "kind": "فرضیه، نه RCA تأییدشده",
        })
    disk_records = by_key["disk"]["evidence"]
    def high_mount_pressure(item):
        return any(
            isinstance(m, dict) and str(m.get("use_percent") or "0").rstrip("%").isdigit()
            and int(str(m.get("use_percent") or "0").rstrip("%")) >= 90
            for m in item.get("facts", {}).get("filesystems", [])
        )
    if by_key["disk"]["status"] == "investigated" and any(
        high_mount_pressure(record) and record.get("freshness") == "fresh"
        for record in disk_records
    ):
        hypotheses.append({
            "title": "فشار ظرفیت Disk یا I/O (صرفاً فرضیه بررسی)",
            "supporting": [record["id"] for record in disk_records
                           if high_mount_pressure(record) and record.get("freshness") == "fresh"],
            "opposing": [],
            "check": "Mount مرتبط، Inode، I/O Latency و زمان خطا را با Startup تطبیق دهید.",
            "confidence": None, "kind": "علت احتمالی تأیید نشده",
        })
    monitoring_alerts = [
        row for row in matching if _source(row) == "zabbix"
        and row.get("type") == "alert" and _state(row, now) == "fresh"
        and str(row.get("raw_data", {}).get("status") or "").lower() in {"problem", "down"}
    ]
    conflicts = []
    if sysfacts.get("active_state") == "active" and sys and sys.get("freshness") == "fresh" and monitoring_alerts:
        conflicts.append({
            "description": "Zabbix وضعیت Problem/Down و VM MCP وضعیت active گزارش کرده‌اند؛ زمان و نوع Health Check را مقایسه کنید.",
            "evidence_refs": [sys["id"]] + [
                str(item.get("id") or item.get("reference") or "") for item in monitoring_alerts[:3]
            ],
            "resolution": "بررسی مستقل HTTP Health و زمان آخرین Problem/Recovery؛ هیچ‌یک را خودکار صحیح فرض نکنید.",
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
        "Stop attribution: " + (stop_origin["note_fa"] if stop_origin else "no stop-timeout hypothesis"),
        "ELK: " + by_key["elastic"]["technical_result"],
        "Journal: " + by_key["journal"]["technical_result"],
        "CPU/RAM: " + by_key["resources"]["technical_result"],
        "Disk: " + by_key["disk"]["technical_result"],
        "اقدام بعدی: " + (actions["read_only"][0]["expected"] if actions["read_only"] else "بررسی شرایط قبل از هر تغییر؛ Approval مستقل الزامی است."),
    ]
    return redact({
        "version": "technical-investigation.v1", "read_only": True,
        "service": service, "host": _text(host) or None,
        "stop_origin": stop_origin,
        "executive_lines": header, "domains": domains,
        "rca": {"confirmed_facts": confirmed, "likely_hypotheses": hypotheses,
                "ruled_out": [], "remaining_unknowns": unknowns,
                "cause_confirmed": False,
                "note": "هم‌زمانی شواهد و وضعیت فرآیند بدون بررسی مستقل، علت ریشه‌ای را اثبات نمی‌کنند."},
        "actions": actions,
        "identity_mismatch_count": mismatched, "conflicts": conflicts,
        "approval_status": str((approval or {}).get("status") or "not_recorded"),
    })
