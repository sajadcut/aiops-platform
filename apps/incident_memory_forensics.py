"""Host-memory Incident RCA: what was checked, what is unknown, what to do.

This is read-only report synthesis, not an action proposal or root-cause
classifier. An alert and a successful recovery webhook do not prove RCA.
"""
from __future__ import annotations

import re
from datetime import datetime, timezone


RAM_ALERT = re.compile(r"(high memory|memory utilization|memory pressure|memory usage|ram usage|مصرف.*(?:رم|حافظه))", re.I)


def obj(value):
    return value if isinstance(value, dict) else {}


def stamp(value):
    try:
        at = value if isinstance(value, datetime) else datetime.fromisoformat(
            str(value).replace("Z", "+00:00"))
        return (at if at.tzinfo else at.replace(tzinfo=timezone.utc)).astimezone(timezone.utc)
    except (TypeError, ValueError):
        return None


def metric(value, maximum=1e10):
    if isinstance(value, bool):
        return None
    try:
        amount = float(value)
        return round(amount, 2) if 0 <= amount <= maximum and amount == amount else None
    except (TypeError, ValueError, OverflowError):
        return None


def is_memory_incident(incident: dict, checkpoint: dict) -> bool:
    state = obj(checkpoint.get("state"))
    signal = obj(obj(state.get("context")).get("trigger_signal"))
    raw = obj(signal.get("raw_data"))
    return any(RAM_ALERT.search(str(item or "")) for item in (
        incident.get("summary"), signal.get("summary"), raw.get("trigger"),
        raw.get("name"), raw.get("description"),
    ))


def build_memory_investigation(*, incident, checkpoint, evidence, audit_events):
    """Parse only durable attributed MCP results, original alert and recovery."""
    if not is_memory_incident(incident, checkpoint):
        return None
    state = obj(checkpoint.get("state"))
    signal = obj(obj(state.get("context")).get("trigger_signal"))
    raw_signal = obj(signal.get("raw_data"))
    content = str(signal.get("summary") or incident.get("summary") or "")
    threshold = re.search(r">\s*(\d{1,3})\s*%", content)
    duration = re.search(r"for\s+(\d{1,3})m\b", content, re.I)
    target = str(raw_signal.get("target_ip") or "").strip()
    host = str(raw_signal.get("host_name") or obj(raw_signal.get("host")).get("name")
               or obj(incident.get("context")).get("host_name") or "").strip()[:125]
    if not re.fullmatch(r"[\w.-]{1,125}", host):
        host = ""
    items = {}
    for row in evidence:
        if not isinstance(row, dict) or row.get("source") != "vm_mcp":
            continue
        raw = obj(row.get("raw_data"))
        diag = str(raw.get("diagnostic") or "")
        if diag not in {"memory_diagnostics", "process_snapshot", "collect_vm_metrics"}:
            continue
        actual_target = str(raw.get("target") or "")
        if not actual_target or (target and actual_target != target):
            continue
        # Do not mix multiple hosts even if service identity is unknown.
        if not target:
            target = actual_target
        when = stamp(row.get("created_at") or row.get("timestamp"))
        if when is None:
            continue
        if diag == "collect_vm_metrics":
            if raw.get("name") != "memory_usage" or metric(raw.get("value"), 100) is None:
                continue
            diag = "memory_usage"
        elif raw.get("success") is not True:
            continue
        prev = items.get(diag)
        if prev is None or when >= prev["at"]:
            items[diag] = {
                "at": when, "raw": raw,
                "ref": str(row.get("reference") or row.get("id") or "")[:160],
            }
    measurements = obj(obj(items.get("memory_diagnostics")).get("raw"))
    generic = obj(obj(items.get("memory_usage")).get("raw"))
    snapshot = obj(obj(items.get("process_snapshot")).get("raw"))
    processes = measurements.get("top_processes") or snapshot.get("processes") or []
    top = []
    for process in processes[:15]:
        if not isinstance(process, dict) or not isinstance(process.get("pid"), int):
            continue
        pct = metric(process.get("memory_percent"), 100)
        if pct is None or process["pid"] <= 0:
            continue
        name = str(process.get("command") or "")[:80]
        if not re.fullmatch(r"[\w@.:-]{1,80}", name):
            name = "process"
        top.append({
            "pid": process["pid"], "name": name, "percent": pct,
            "rss_mb": metric(process.get("rss_mb")),
        })
    top.sort(key=lambda x: x["rss_mb"] if x["rss_mb"] is not None else x["percent"], reverse=True)
    def status(code, label):
        item = items.get(code)
        return {
            "code": code, "title_fa": label,
            "status": "checked" if item else "not_collected",
            "evidence_refs": [item["ref"]] if item and item["ref"] else [],
            "observed_at": item["at"].isoformat() if item else None,
        }
    checks = [
        status("memory_usage", "درصد واقعی مصرف RAM از VM MCP"),
        status("memory_diagnostics", "MemAvailable، Cache، Swap و PSI"),
        status("process_snapshot", "فهرست پردازش‌های پرمصرف"),
    ]
    recovery_events = [
        event for event in audit_events if isinstance(event, dict)
        and event.get("event_type") == "verification_source_recovery_received"
        and str(event.get("actor") or "") in {"zabbix_webhook", "zabbix"}
    ]
    recovered = bool(recovery_events) or str(incident.get("status") or "").lower() == "resolved"
    recovery_times = [stamp(event.get("created_at")) for event in recovery_events]
    recovery_times = [x for x in recovery_times if x]
    facts = ["هشدار Zabbix عبور مصرف RAM از آستانه را گزارش کرده است."]
    if recovered:
        facts.append("پیام رفع هشدار از منبع مانیتورینگ ثبت شده؛ علت مصرف RAM ثابت نشده است.")
    if top:
        facts.append("پردازش‌های پرمصرف در یک لحظه ثبت شده‌اند؛ عامل رشد تاریخی هنوز تأیید نشده است.")
    gaps = []
    if not items.get("memory_diagnostics"):
        gaps.append("اطلاعات RAM قابل‌بازیابی، Cache، Swap و PSI از VM MCP ثبت نشده است.")
    if not top:
        gaps.append("هیچ فهرست معتبری از پردازش‌های پرمصرف و RSS ثبت نشده است.")
    if not raw_signal.get("target_ip"):
        gaps.append("فیلد صریح target_ip در آلارم ثبت نشده؛ نام میزبان یا IP داخل متن Agent مجوز اتصال به VM نیست.")
    gaps.append("بدون روند تاریخی و دو نمونهٔ RSS، Memory Leak، رشد Cache یا پردازش مقصر قابل تأیید نیست.")
    actions = [
        {"title_fa": "بررسی RAM، Cache، Swap، PSI و پردازش‌ها",
         "detail_fa": "پس از تأیید صریح target_ip در آلارم، memory_diagnostics و collect_vm_metrics و process_snapshot را از VM MCP اجرا کنید. اطلاعات ابزار باید دارای زمان و شناسهٔ شاهد باشند.",
         "checks": ["memory_diagnostics", "collect_vm_metrics", "process_snapshot"],
         "type": "read_only"},
        {"title_fa": "مقایسهٔ روند تاریخی قبل، حین و بعد از هشدار",
         "detail_fa": "نمودار مصرف و MemAvailable و Swap را در Zabbix/Prometheus بررسی کنید؛ دو نمونهٔ مستقل PID/RSS به تشخیص رشد واقعی کمک می‌کند.",
         "checks": ["zabbix_history", "prometheus_range"], "type": "read_only"},
        {"title_fa": "بررسی خطاهای OOM و فشار حافظه",
         "detail_fa": "لاگ Kernel/OOM، تغییرات اخیر فرایندها و وابستگی‌ها را مرور کنید. یک مقدار بالای RAM به‌تنهایی نشتی حافظه نیست.",
         "checks": ["system_logs", "memory_diagnostics"], "type": "read_only"},
        {"title_fa": "پایش پس از Recovery و تصمیم مستقل",
         "detail_fa": "رفع هشدار به‌معنی اجرای عملیات AIOps نیست. Restart، Kill، پاک‌سازی Cache یا افزایش RAM بدون شواهد و Approval مستقل پیشنهاد اجرایی محسوب نمی‌شوند.",
         "checks": [], "type": "operator_review"},
    ]
    return {
        "kind": "host_memory_investigation",
        "host": host or None, "observed_target": target or None,
        "alert_target_ip": raw_signal.get("target_ip"),
        "target_binding_missing": not bool(raw_signal.get("target_ip")),
        "alert": {
            "source": "zabbix", "threshold_percent": int(threshold.group(1)) if threshold else None,
            "duration_minutes": int(duration.group(1)) if duration else None,
            "recovery_received": recovered,
            "recovery_time": max(recovery_times).isoformat() if recovery_times else None,
        },
        "measurements": {
            "memory_used_percent": metric(measurements.get("used_percent"), 100) or metric(generic.get("value"), 100),
            "total_mb": metric(measurements.get("total_mb")),
            "available_mb": metric(measurements.get("available_mb")),
            "cache_reclaimable_mb": metric(measurements.get("cache_reclaimable_mb")),
            "swap_used_mb": metric(measurements.get("swap_used_mb")),
            "swap_total_mb": metric(measurements.get("swap_total_mb")),
            "psi_memory_some_avg10": metric(measurements.get("psi_memory_some_avg10"), 100),
            "top_processes": top[:8],
        },
        "checks": checks, "confirmed": facts, "gaps": gaps,
        "root_cause_status": "not_proven",
        "recommended_next_checks": actions,
        "source_recovery_not_action_verification": True,
        "execution_authority": False,
    }
