"""Read-only incident state correlation: direct, attributed and time-aware.

A Zabbix down alert and a later VM MCP "active" observation prove two
source statements, not necessarily a recovery or a false positive. This
module cannot approve or execute changes. Every claim retains its origin.
"""
from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any, Iterable, Mapping


def _obj(v: Any) -> dict:
    return v if isinstance(v, dict) else {}


def _name(v: Any) -> str:
    text = str(v or "").strip().lower()
    return text[:-8] if text.endswith(".service") else text


def _stamp(v: Any) -> datetime | None:
    try:
        t = v if isinstance(v, datetime) else datetime.fromisoformat(str(v).replace("Z", "+00:00"))
        return t.astimezone(timezone.utc) if t.tzinfo else None
    except (ValueError, TypeError, OverflowError):
        return None


def _timestamp(v: Any) -> str | None:
    t = _stamp(v)
    return t.isoformat() if t else None


def _ref(row: Mapping) -> str | None:
    x = row.get("id") or row.get("evidence_id") or row.get("reference")
    return str(x)[:160] if x else None


def _down(text: Any) -> bool:
    t = str(text or "").lower()
    return bool(re.search(r"\b(service\s+down|systemd\s+.*down|is-active.*inactive|inactive\s*\(dead\)|"
                          r"active_state\s*=\s*(?:inactive|failed)|service\s+(?:failed|inactive))\b", t))


def _up(raw: dict) -> bool:
    return str(raw.get("active_state") or "").lower() == "active" and str(
        raw.get("sub_state") or "").lower() in {"running", "exited"}


def _stopped(raw: dict) -> bool:
    return str(raw.get("active_state") or "").lower() in {"failed", "inactive"}


def _signal(incident: dict, checkpoint: dict) -> dict:
    context = _obj(incident.get("context"))
    state = _obj(checkpoint.get("state"))
    workflow = _obj(state.get("context"))
    for candidate in (workflow.get("trigger_signal"), context.get("trigger_signal")):
        if isinstance(candidate, dict):
            kind = str(candidate.get("source") or candidate.get("provider") or "").lower()
            if kind in {"zabbix", "zabbix_webhook"}:
                return candidate
    return {}


def _trigger(incident: dict, checkpoint: dict) -> dict:
    sig = _signal(incident, checkpoint)
    raw = _obj(sig.get("raw_data"))
    payload = _obj(sig.get("payload"))
    original = _obj(raw.get("_received_payload"))
    nested = _obj(payload.get("_received_payload"))
    view = original or nested or payload or raw
    text = str(sig.get("summary") or view.get("message") or view.get("name")
               or raw.get("signal_summary") or "")
    # A generic normalized 'timestamp' can mean ingestion time. Only an
    # original captured payload, or an explicitly named event field, may
    # establish source occurrence time.
    captured = original or nested
    event_time = (
        captured.get("event_time") or captured.get("occurred_at")
        or captured.get("startsAt") or captured.get("timestamp")
        or raw.get("event_time") or raw.get("occurred_at")
        or payload.get("event_time") or payload.get("occurred_at")
    )
    precise = bool(event_time and re.search(r"T\d{2}:\d{2}:\d{2}", str(event_time)))
    # Signal timestamp is ingestion/receipt in many workflows; it is NOT
    # a verified Zabbix event timestamp without explicit source provenance.
    named = _name(raw.get("service") or payload.get("service") or view.get("service")
                  or _obj(view.get("tags")).get("service"))
    target = str(raw.get("target_ip") or payload.get("target_ip") or
                 view.get("target_ip") or "").strip()
    return {
        "valid": bool(sig),
        "source": "zabbix" if sig else None,
        "reported_down": _down(text) or _down(raw.get("trigger") or raw.get("name")),
        "service": named, "target": target,
        "observed_at": _timestamp(event_time),
        "time_basis": ("source_event" if _timestamp(event_time) and precise else
                       "source_event_minute_only" if _timestamp(event_time) else "not_recorded"),
        "received_at": _timestamp(sig.get("timestamp") or sig.get("received_at")),
        "evidence_refs": [str(sig.get("evidence_id"))[:160]] if sig.get("evidence_id") else [],
    }


def _vm_records(evidence: Iterable[dict], service: str, target: str | None) -> list[dict]:
    rows = []
    for row in evidence:
        if not isinstance(row, dict) or row.get("source") != "vm_mcp":
            continue
        raw = _obj(row.get("raw_data"))
        if (raw.get("diagnostic") != "service_status" or raw.get("success") is not True
                or _name(raw.get("service")) != service
                or not (_up(raw) or _stopped(raw))):
            continue
        host = str(raw.get("target") or "").strip()
        if not host or (target and host != target):
            continue
        observed = _timestamp(raw.get("collected_at") or raw.get("observed_at")
                              or raw.get("timestamp") or row.get("created_at"))
        rows.append({
            "source": "vm_mcp", "service": service, "target": host,
            "active_state": str(raw.get("active_state") or "").lower(),
            "sub_state": str(raw.get("sub_state") or "").lower(),
            "main_pid": raw.get("main_pid") if type(raw.get("main_pid")) is int else None,
            "result": str(raw.get("result") or "")[:40] or None,
            "observed_at": observed, "time_basis": "vm_mcp_collection" if observed else "not_recorded",
            "evidence_refs": [_ref(row)] if _ref(row) else [],
        })
    # Do not choose "latest" based on insertion order if timestamps missing.
    return sorted(rows, key=lambda x: (x["observed_at"] is not None, x["observed_at"] or ""),
                  reverse=True)


def _http_observation(events: Iterable[dict], service: str, target: str | None) -> dict | None:
    matches = []
    for event in events:
        if not isinstance(event, dict) or event.get("event_type") != "service_http_health_rechecked":
            continue
        metadata = _obj(event.get("metadata"))
        if (_name(metadata.get("service")) != service
                or not target or str(metadata.get("target") or "") != target):
            continue
        status = str(metadata.get("status") or "").lower()
        if status not in {"healthy", "unhealthy", "unavailable"}:
            continue
        at = _timestamp(event.get("created_at"))
        if at:
            matches.append({"status": status, "observed_at": at, "source": "http_health_audit",
                            "evidence_refs": [str(event.get("event_id"))[:160]]
                            if event.get("event_id") else []})
    return max(matches, key=lambda x: x["observed_at"]) if matches else None


def correlate_incident_state(*, incident: dict, checkpoint: dict,
                             evidence: Iterable[dict], audit_events: Iterable[dict] = (),
                             now: datetime | None = None) -> dict:
    """Present source disagreement, not invented causal resolution.

    Only a repeated *direct VM status* observation can prove the systemd
    state changed. A Zabbix-vs-VM disagreement alone is insufficient.
    """
    now = now or datetime.now(timezone.utc)
    service = _name(incident.get("service") or _obj(checkpoint.get("state")).get("service_name"))
    trigger = _trigger(incident, checkpoint)
    if not service or service in {"unknown", "unidentified", "service"}:
        return {"kind": "no_verified_service", "read_only": True,
                "headline_fa": None, "contradictions": [], "hypotheses": []}
    target = trigger.get("target") or None
    rows = _vm_records(evidence, service, target)
    hosts = {x["target"] for x in rows}
    target_conflict = (len(hosts) > 1 and not target)
    if target_conflict:
        rows = []
    host = target or (next(iter(hosts)) if len(hosts) == 1 else None)
    last = rows[0] if rows and rows[0]["observed_at"] else None
    http = _http_observation(audit_events, service, host)
    contradictions, hypotheses, confirmed, gaps, steps = [], [], [], [], []
    alert_matches = bool(trigger["valid"] and trigger["reported_down"]
                         and (not trigger["service"] or trigger["service"] == service)
                         and (not trigger["target"] or trigger["target"] == host))
    if alert_matches:
        confirmed.append({
            "text_fa": f"Zabbix در هشدار ثبت‌شده، سرویس {service} را Down/inactive گزارش کرده است؛ این گزارش وضعیت زندهٔ فعلی نیست.",
            "source": "zabbix", "observed_at": trigger["observed_at"],
            "time_basis": trigger["time_basis"], "evidence_refs": trigger["evidence_refs"],
        })
    if last:
        state = "Running" if last["active_state"] == "active" else last["active_state"]
        confirmed.append({
            "text_fa": f"VM MCP سرویس {service} را از دید systemd در وضعیت {state} مشاهده کرده است؛ این مشاهده فقط مربوط به زمان ثبت آن است.",
            "source": "vm_mcp", "observed_at": last["observed_at"],
            "time_basis": last["time_basis"], "evidence_refs": last["evidence_refs"],
        })
    # Direct evidence from another host must never be mixed into the incident.
    has_discrepancy = bool(alert_matches and last and last["active_state"] == "active")
    vm_transition = None
    if last and len(rows) > 1:
        prior = next((r for r in rows[1:]
                      if r["observed_at"] and r["observed_at"] < last["observed_at"]
                      and r["target"] == last["target"]
                      and _stopped(r)), None)
        if prior and _up(last):
            vm_transition = {"from": prior, "to": last, "kind": "direct_vm_state_transition"}
    if has_discrepancy:
        # A timestamped alert is still a *different source*; do not pretend
        # Zabbix alone proves a prior real systemd stop.
        relation = "undetermined"
        if (trigger["time_basis"] == "source_event" and
                trigger["observed_at"] and last["observed_at"]):
            if trigger["observed_at"] < last["observed_at"]:
                relation = "alert_event_before_vm_observation"
            elif trigger["observed_at"] > last["observed_at"]:
                relation = "vm_observation_before_alert_event"
            else:
                relation = "same_timestamp_no_order"
        refs = list(dict.fromkeys(trigger["evidence_refs"] + last["evidence_refs"]))
        contradictions.append({
            "contradiction_type": "zabbix_down_vs_vm_systemd_running",
            "affected_service": service, "host": host,
            "source_a": {"source": "zabbix", "reported_state": "down",
                         "observed_at": trigger["observed_at"], "time_basis": trigger["time_basis"]},
            "source_b": {"source": "vm_mcp", "reported_state": "running",
                         "observed_at": last["observed_at"], "time_basis": last["time_basis"]},
            "observed_at": last["observed_at"], "evidence_refs": refs,
            "interpretation": "source_state_discrepancy_not_proven_recovery",
            "temporal_relation": relation,
            "possible_explanations": [
                "temporary_stop_and_recovery", "stale_or_incorrect_monitoring",
                "systemd_running_but_http_unhealthy"],
            "required_checks": ["zabbix_event_time_and_item_history",
                                "systemd_start_timestamp_and_journal",
                                "trusted_http_health_endpoint"],
            "confidence": None, "operational_impact": "recheck_read_only_before_remediation",
        })
        headline = (f"اختلاف وضعیت شناسایی شد: Zabbix برای {service} هشدار Down ثبت کرده، "
                    f"اما VM MCP وضعیت Running در systemd مشاهده کرده است.")
        gaps.extend([
            "هنوز ثابت نشده سرویس پس از هشدار بازیابی شده یا هشدار Zabbix اشتباه بوده است؛ باید زمان دقیق Event، مقدار Item و زمان تغییر وضعیت systemd مقایسه شوند.",
            "Running در systemd سلامت HTTP API یا وابستگی‌های برنامه را تأیید نمی‌کند.",
        ])
        steps.extend([
            "مقایسهٔ Event Time، Trigger Expression، Item History و Recovery Event در Zabbix با زمان Start سرویس در systemd.",
            "بررسی Read-only زمان Start، MainPID، RestartCount و Journal همین سرویس برای تشخیص توقف موقت یا خطای نمونه‌برداری.",
            "پس از ثبت پورت و Health Endpoint معتبر، بررسی HTTP Health و Listener/TCP بدون اجرای Start یا Restart.",
        ])
        hypotheses = [
            {"kind": "temporary_stop_and_recovery", "status": "unverified",
             "supporting_evidence_refs": [r for x in (vm_transition or {}).values()
                                          if isinstance(x, dict) for r in x.get("evidence_refs", [])],
             "opposing_evidence_refs": [], "confidence": None,
             "discriminating_checks": ["systemd_restart_and_start_time", "zabbix_event_history"]},
            {"kind": "stale_or_incorrect_monitoring", "status": "unverified",
             "supporting_evidence_refs": [], "opposing_evidence_refs": [], "confidence": None,
             "discriminating_checks": ["zabbix_item_key", "trigger_expression", "item_history"]},
            {"kind": "systemd_running_but_http_unhealthy", "status": "unverified",
             "supporting_evidence_refs": [], "opposing_evidence_refs": [], "confidence": None,
             "discriminating_checks": ["http_health", "listener", "tcp_reachability"]},
        ]
    else:
        headline = (f"VM MCP سرویس {service} را در وضعیت "
                    f"{'Running' if last and last['active_state']=='active' else last['active_state']} ثبت کرده است؛ "
                    "وضعیت فعلی و علت هشدار باید با بررسی تازه تأیید شود.") if last else None
    if vm_transition:
        confirmed.append({
            "text_fa": "دو مشاهدهٔ مستقیم VM MCP با ترتیب زمانی معتبر، تغییر وضعیت systemd از توقف به Running را ثبت کرده‌اند؛ علت این تغییر هنوز اثبات نشده است.",
            "source": "vm_mcp", "observed_at": vm_transition["to"]["observed_at"],
            "evidence_refs": vm_transition["from"]["evidence_refs"] + vm_transition["to"]["evidence_refs"],
        })
    if http and last and http["status"] == "unhealthy" and last["active_state"] == "active":
        contradictions.append({
            "contradiction_type": "systemd_running_but_http_unhealthy",
            "affected_service": service, "host": host,
            "source_a": {"source": "vm_mcp", "reported_state": "running", "observed_at": last["observed_at"]},
            "source_b": {"source": "http_health_audit", "reported_state": "unhealthy", "observed_at": http["observed_at"]},
            "observed_at": http["observed_at"],
            "evidence_refs": last["evidence_refs"] + http["evidence_refs"],
            "interpretation": "process_up_api_not_healthy", "possible_explanations": [],
            "required_checks": ["application_logs", "listener", "dependencies"],
            "confidence": None, "operational_impact": "api_health_not_confirmed",
        })
        gaps.append("در تست HTTP، API ناسالم ثبت شده؛ اجرای systemd نمی‌تواند جایگزین بررسی خطای برنامه باشد.")
        if has_discrepancy:
            hypotheses[2]["status"] = "supported_not_confirmed"
            hypotheses[2]["supporting_evidence_refs"] = http["evidence_refs"]
    elif not http:
        gaps.append("سلامت HTTP در شواهد این Incident بررسی یا تأیید نشده است.")
    if target_conflict:
        gaps.append("شواهد VM MCP به چند میزبان متفاوت اشاره دارند؛ وضعیت آن‌ها برای نتیجه‌گیری با هم ترکیب نشده است.")
    if not trigger["observed_at"] and alert_matches:
        gaps.append("زمان وقوع دقیق از دید Zabbix ثبت نشده است؛ زمان دریافت هشدار به‌جای زمان Event استفاده نمی‌شود.")
    if not last and alert_matches:
        gaps.append("مشاهدهٔ موفق و دارای زمان از VM MCP برای همین سرویس و میزبان ثبت نشده است.")
        steps.append("اجرای استعلام فقط خواندنی service_status روی مقصد مجاز و دارای هویت تأییدشده.")
    # Never turn ps -C <service> = no matches into proof MainPID is zero.
    process = next((r for r in evidence if isinstance(r, dict) and r.get("source")=="vm_mcp"
                    and isinstance(r.get("raw_data"), dict)
                    and r["raw_data"].get("diagnostic")=="process_status"
                    and r["raw_data"].get("success") is True
                    and r["raw_data"].get("running") is False
                    and _name(r["raw_data"].get("service")) == service
                    and (not host or str(r["raw_data"].get("target") or "") == host)), None)
    if process and last and last["active_state"] == "active":
        gaps.append("Process Check تطبیق نام سرویس را پیدا نکرده، اما systemd فعال است؛ برای .NET باید MainPID و فرایند dotnet/CGroup تطبیق داده شوند.")
        steps.append("بررسی Read-only MainPID و Process Executable/CGroup؛ نتیجهٔ ps -C به‌تنهایی دلیل توقف برنامه نیست.")
    if not steps and alert_matches:
        steps.append("استعلام read-only وضعیت systemd و مقایسه با Event History زبیکس، بدون اجرای تغییر.")
    return {
        "kind": "incident_state_correlation",
        "service": service, "host": host,
        "alert": trigger, "last_vm_observation": last, "http_observation": http,
        "headline_fa": headline,
        "conclusion_kind": ("source_discrepancy" if has_discrepancy else
                            "direct_vm_observation" if last else "insufficient_direct_evidence"),
        "conclusion_fa": (headline + " " + ("ترتیب دقیق علت و بازیابی هنوز اثبات نشده است."
                           if has_discrepancy else "این نتیجه یک مشاهدهٔ ثبت‌شده است، نه بررسی زنده."))
                         if headline else None,
        "contradictions": contradictions,
        "confirmed_observations": confirmed,
        "confirmed_vm_transition": vm_transition,
        "hypotheses": hypotheses,
        "unknowns_fa": gaps[:7], "next_steps_fa": steps[:5],
        "read_only": True, "authorizes_execution": False, "root_cause_verified": False,
    }
