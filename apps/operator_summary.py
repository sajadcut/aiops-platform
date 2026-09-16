from __future__ import annotations

import re
from typing import Any, Dict, Iterable, List, Optional

CONFIDENCE_FA = {"confirmed": "تأیید شده", "probable": "محتمل", "unknown": "نامشخص"}
AUTOMATION = re.compile(r"\b(aiops|execution_service|e2e_orchestrator|mcp|automation|bot)\b", re.I)
HUMAN = re.compile(r"\bsudo:\s*[^:]+:.*\bcommand=|\bauid=\d+\b|\b(actor|user|username|initiated_by|requested_by)\s*[=:]\s*[\w.@-]+", re.I)
DIRECT_LOG_DIAGNOSTICS = {"service_logs", "system_logs", "journalctl", "journal", "journald", "audit_log", "auditd"}
ACTIONS = (
    ("manual_stop", "Manual Stop", re.compile(r"\bsystemctl\s+stop\s+[\w@.:-]+|\bservice\s+[\w@.:-]+\s+stop\b|\bstop_service\b|\bmanual[_ -]stop\b", re.I)),
    ("restart", "Restart", re.compile(r"\bsystemctl\s+restart\s+[\w@.:-]+|\bservice\s+[\w@.:-]+\s+restart\b|\brestart_service\b", re.I)),
    ("configuration_change", "Configuration Change", re.compile(r"\b(configuration|config)[_ -]?(change|changed|updated|modified)\b|\b(sed|tee|vim|vi|nano)\b.*\b(/etc/|\.conf\b)", re.I)),
    ("deployment", "Deployment", re.compile(r"\b(deploy|deployment|release|rollout)\b", re.I)),
)


def _t(value: Any) -> str:
    if value in (None, ""):
        return ""
    return str(getattr(value, "value", value)).strip()


def _low(value: Any) -> str:
    return _t(value).lower()


def _d(value: Any) -> Dict[str, Any]:
    return dict(value) if isinstance(value, dict) else {}


def _l(value: Any) -> List[Any]:
    return list(value) if isinstance(value, (list, tuple)) else []


def _true(value: Any) -> bool:
    return value is True or _low(value) == "true"


def _context_value(context: Dict[str, Any], keys: Iterable[str]) -> Any:
    """Read a scalar fallback from durable Incident Context without turning context into Evidence."""
    for wanted in keys:
        queue: List[Any] = [context]
        scanned = 0
        while queue and scanned < 100:
            node = queue.pop(0)
            scanned += 1
            if isinstance(node, dict):
                for key, value in node.items():
                    if _low(key) == wanted and not isinstance(value, (dict, list, tuple, set)) and _t(value):
                        return value
                    if isinstance(value, (dict, list, tuple)):
                        queue.append(value)
            elif isinstance(node, (list, tuple)):
                queue.extend(value for value in node if isinstance(value, (dict, list, tuple)))
    return None


def _norm(item: Dict[str, Any]) -> Dict[str, Any]:
    raw = _d(item.get("raw_data"))
    ref = _t(item.get("id") or item.get("evidence_id") or item.get("reference"))
    return {
        "id": ref or None,
        "reference": _t(item.get("reference")) or ref or None,
        "source": _t(item.get("source")) or "unknown",
        "type": _t(item.get("type")) or "unknown",
        "raw_data": raw,
        "confidence": item.get("confidence"),
        "created_at": item.get("created_at") or item.get("timestamp"),
    }


def _key(item: Dict[str, Any]) -> str:
    raw = _d(item.get("raw_data"))
    return _t(item.get("id") or item.get("reference")) or "|".join(
        _t(x) for x in (item.get("source"), item.get("type"), raw.get("diagnostic"), raw.get("target"), item.get("created_at"))
    )


def _ref(item: Optional[Dict[str, Any]]) -> Optional[str]:
    return (_t((item or {}).get("id") or (item or {}).get("reference")) or None)


def _merge_evidence(state: Dict[str, Any], durable: Iterable[Dict[str, Any]], audit: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    context, after = _d(state.get("context")), _d(state.get("after_context"))
    buckets = [
        _d(context.get("post_execution_evidence")).get("evidence"),
        _d(after.get("live_evidence")).get("evidence"),
        _d(state.get("live_evidence")).get("evidence"),
        context.get("evidence"), context.get("trigger_evidence"),
    ]
    rows: List[Dict[str, Any]] = []
    for bucket in buckets:
        rows.extend(_norm(x) for x in _l(bucket) if isinstance(x, dict))
    rows.extend(_norm(x) for x in durable if isinstance(x, dict))
    for event in audit:
        raw = _d(event.get("metadata"))
        raw.update({"event_type": event.get("event_type"), "actor": event.get("actor"), "action": event.get("action"), "status": event.get("status")})
        rows.append(_norm({"id": event.get("event_id"), "source": "audit", "type": "event", "raw_data": raw, "created_at": event.get("created_at"), "confidence": 1.0}))
    out, seen = [], set()
    for row in rows:
        key = _key(row)
        if key and key in seen:
            continue
        if key:
            seen.add(key)
        out.append(row)
    return out


def _diag(rows: List[Dict[str, Any]], name: str) -> Optional[Dict[str, Any]]:
    return next((x for x in rows if _low(_d(x.get("raw_data")).get("diagnostic")) == name), None)


def _human_action(rows: List[Dict[str, Any]]) -> Dict[str, Any]:
    for item in rows:
        raw, source = _d(item.get("raw_data")), _low(item.get("source"))
        diagnostic = _low(raw.get("diagnostic"))
        if source not in {"audit", "vm_mcp", "systemd", "journal", "journald", "linux_audit", "auditd"} and diagnostic not in DIRECT_LOG_DIAGNOSTICS:
            continue
        if source == "audit" and any(x in _low(raw.get("event_type")) for x in ("approval", "decision")):
            continue
        values = [raw.get(k) for k in ("message", "detail", "event", "command", "action", "actor", "user", "username", "initiated_by", "requested_by")]
        values += _l(raw.get("entries") or raw.get("logs"))
        text = "\n".join(_t(x) for x in values if _t(x))
        actor_type = _low(raw.get("actor_type") or raw.get("initiator_type") or raw.get("principal_type"))
        actor = " ".join(_t(raw.get(k)) for k in ("actor", "user", "username", "initiated_by", "requested_by"))
        structured_human = actor_type in {"human", "user", "operator", "admin", "administrator"} or (actor and not AUTOMATION.search(actor))
        if not text or AUTOMATION.search(text) or not (structured_human or HUMAN.search(text)):
            continue
        for kind, label, pattern in ACTIONS:
            if pattern.search(text):
                ref = _ref(item)
                return {"type": kind, "label": label, "status": "confirmed", "status_fa": CONFIDENCE_FA["confirmed"], "text_fa": f"{label} با شواهد مستقیم ثبت‌شده مشاهده شده است.", "evidence_ids": [ref] if ref else []}
    service = _diag(rows, "service_status")
    raw = _d((service or {}).get("raw_data"))
    clean = _low(raw.get("active_state") or raw.get("status")) == "inactive" and _low(raw.get("sub_state")) == "dead" and str(raw.get("exec_main_status")) == "0" and _low(raw.get("result")) == "success"
    if clean:
        ref = _ref(service)
        return {"type": "manual_stop", "label": "Manual Stop", "status": "probable", "status_fa": CONFIDENCE_FA["probable"], "text_fa": "توقف دستی محتمل است، اما شواهد مستقیم برای نسبت‌دادن توقف به اقدام انسان موجود نیست.", "evidence_ids": [ref] if ref else []}
    return {"type": "unknown", "label": "Unknown", "status": "unknown", "status_fa": CONFIDENCE_FA["unknown"], "text_fa": "شواهد کافی برای تأیید اقدام دستی انسان موجود نیست.", "evidence_ids": []}


def _observed(incident: Dict[str, Any], state: Dict[str, Any], rows: List[Dict[str, Any]]) -> Dict[str, Any]:
    items = {name: _diag(rows, name) for name in ("service_status", "process_status", "port_listener_status", "tcp_check", "config_validate")}
    raw = {name: _d((item or {}).get("raw_data")) for name, item in items.items()}
    request, live, state_context = _d(state.get("execution_request")), _d(state.get("live_evidence")), _d(state.get("context"))
    incident_context = _d(incident.get("context"))
    context_target = _context_value(incident_context, ("vm_target", "target_ip", "ip_address", "ip", "hostname", "host", "target", "address"))
    context_port = _context_value(incident_context, ("target_port", "service_port", "port"))
    context_service = _context_value(incident_context, ("service_name", "service"))

    target_candidates = (
        (raw["service_status"].get("target"), "service_status"),
        (raw["process_status"].get("target"), "process_status"),
        (raw["port_listener_status"].get("target"), "port_listener_status"),
        (raw["tcp_check"].get("target"), "tcp_check"),
        (live.get("vm_target"), "live_evidence"),
        (request.get("target"), "execution_request"),
        (_d(state_context.get("live_evidence")).get("vm_target"), "workflow_context"),
        (context_target, "incident_context"),
    )
    target, target_source = next(((_t(value), source) for value, source in target_candidates if _t(value)), ("", None))

    port_candidates = (
        (raw["port_listener_status"].get("port") or raw["port_listener_status"].get("target_port"), "port_listener_status"),
        (raw["tcp_check"].get("port") or raw["tcp_check"].get("target_port"), "tcp_check"),
        (live.get("vm_port"), "live_evidence"),
        (_d(request.get("parameters")).get("target_port"), "execution_request"),
        (context_port, "incident_context"),
    )
    port_value, port_source = next(((value, source) for value, source in port_candidates if value not in (None, "")), (None, None))
    try:
        port = int(port_value) if port_value not in (None, "") else None
        if port is not None and not 0 < port <= 65535:
            port, port_source = None, None
    except (TypeError, ValueError):
        port, port_source = None, None

    service_candidates = (
        (incident.get("service"), "incident"),
        (state.get("service_name"), "workflow_state"),
        (raw["service_status"].get("service"), "service_status"),
        (context_service, "incident_context"),
    )
    service, service_source = next(((_t(value), source) for value, source in service_candidates if _t(value)), ("unknown", None))

    metrics = {}
    for item in rows:
        value = _d(item.get("raw_data"))
        if _low(value.get("diagnostic")) == "collect_vm_metrics" or _low(item.get("type")) == "metric":
            if _t(value.get("name")) and value.get("value") is not None:
                metrics.setdefault(_t(value.get("name")), value.get("value"))
    def view(name: str, fields: List[str]) -> Optional[Dict[str, Any]]:
        if not items[name]:
            return None
        result = {k: raw[name].get(k) for k in fields}
        result["evidence_id"] = _ref(items[name])
        return result
    return {
        "service": service,
        "target": target or None, "port": port,
        "field_sources": {"service": service_source, "target": target_source, "port": port_source},
        "incident_context": {"service": _t(context_service) or None, "target": _t(context_target) or None, "port": context_port},
        "service_status": view("service_status", ["active_state", "sub_state", "result", "exec_main_status", "main_pid", "restart_count"]),
        "process_status": view("process_status", ["running", "count"]),
        "port_listener_status": view("port_listener_status", ["supported", "listening"]),
        "tcp_check": view("tcp_check", ["supported", "reachable"]),
        "config_validate": view("config_validate", ["supported", "valid"]),
        "metrics": metrics,
    }


def _cause(observed: Dict[str, Any], human: Dict[str, Any], state: Dict[str, Any], findings: List[Dict[str, Any]]) -> tuple[str, str, List[str]]:
    status, service = _d(observed.get("service_status")), _t(observed.get("service")) or "سرویس"
    active, sub, result = _low(status.get("active_state")), _low(status.get("sub_state")), _low(status.get("result"))
    ref = _t(status.get("evidence_id"))
    if active == "inactive" and human.get("type") == "manual_stop" and human.get("status") == "confirmed":
        refs = list(human.get("evidence_ids") or [])
        if ref and ref not in refs:
            refs.append(ref)
        return "توقف دستی سرویس — تأیید شده", "confirmed", refs
    if active == "inactive" and sub == "dead" and status.get("exec_main_status") in (0, "0") and result == "success":
        return "سرویس به‌صورت Clean متوقف شده است؛ توقف دستی محتمل است ولی از شواهد فعلی قابل تأیید نیست.", "probable", [ref] if ref else []
    if active and active != "active":
        return f"{service} در وضعیت {active}{('/' + sub) if sub else ''} مشاهده شده است؛ علت دقیق از شواهد فعلی قابل تأیید نیست.", "unknown", [ref] if ref else []
    triage, coordination = _d(state.get("triage_result")), _d(state.get("coordination"))
    candidate, refs = _t(triage.get("likely_cause")), [str(x) for x in _l(triage.get("evidence_ids")) if _t(x)]
    if not candidate:
        for h in _l(coordination.get("consensus_hypotheses")):
            candidate = _t((_d(h).get("statement") or _d(h).get("hypothesis") or _d(h).get("cause")) if isinstance(h, dict) else h)
            if candidate:
                refs = [str(x) for x in _l(_d(h).get("evidence_ids")) if _t(x)] if isinstance(h, dict) else []
                break
    if not candidate:
        for row in findings:
            if "cause" in _low(row.get("finding_type")) or "root" in _low(row.get("finding_type")):
                candidate, refs = _t(row.get("statement")), [str(x) for x in _l(row.get("evidence_ids")) if _t(x)]
                if candidate:
                    break
    if candidate and any(x in candidate.lower() for x in ("manual stop", "manually stopped", "human stop", "توقف دستی")) and human.get("status") != "confirmed":
        return "عامل توقف از شواهد مستقیم فعلی قابل تأیید نیست.", "unknown", refs
    return (candidate, "probable", refs) if candidate else ("علت رخداد از شواهد فعلی مشخص نشده است.", "unknown", [])


def _evidence_summary(item: Dict[str, Any]) -> str:
    raw, diag = _d(item.get("raw_data")), _low(_d(item.get("raw_data")).get("diagnostic"))
    if diag == "service_status":
        return "service_status: " + ", ".join(f"{k}={raw.get(k)}" for k in ("active_state", "sub_state", "result", "exec_main_status", "main_pid") if raw.get(k) is not None)
    if diag == "process_status": return f"process_status: running={raw.get('running')}, count={raw.get('count')}"
    if diag == "port_listener_status": return f"port_listener_status: port={raw.get('port') or raw.get('target_port')}, listening={raw.get('listening')}"
    if diag == "tcp_check": return f"tcp_check: host={raw.get('host') or raw.get('target')}, port={raw.get('port') or raw.get('target_port')}, reachable={raw.get('reachable')}"
    if diag in DIRECT_LOG_DIAGNOSTICS:
        entries = _l(raw.get("entries") or raw.get("logs")); tail = _t(entries[-1])[:220] if entries else ""
        return f"{diag}: count={raw.get('count', len(entries))}" + (f", latest={tail}" if tail else "")
    if diag == "config_validate": return f"config_validate: supported={raw.get('supported')}, valid={raw.get('valid')}"
    if diag == "collect_vm_metrics" or _low(item.get("type")) == "metric": return f"{_t(raw.get('name')) or 'metric'}={raw.get('value')}"
    return _t(item.get("reference")) or f"{item.get('source')} {item.get('type')}"


def _observed_text(o: Dict[str, Any]) -> str:
    location = f" روی {o.get('target')}" if o.get("target") else ""
    if o.get("port"): location += f" پورت {o['port']}"
    parts, svc = [], _d(o.get("service_status"))
    if svc:
        state = "/".join(x for x in (_t(svc.get("active_state")), _t(svc.get("sub_state"))) if x)
        if state: parts.append(f"وضعیت سرویس {state} است")
    proc, port, tcp = _d(o.get("process_status")), _d(o.get("port_listener_status")), _d(o.get("tcp_check"))
    if proc.get("running") is not None: parts.append("Process فعال است" if proc.get("running") else "Process فعال نیست")
    if port.get("listening") is not None: parts.append("Port در حال Listen است" if port.get("listening") else "Port در حال Listen نیست")
    if tcp.get("reachable") is not None: parts.append("TCP قابل دسترس است" if tcp.get("reachable") else "TCP قابل دسترس نیست")
    return f"برای {o.get('service')}{location}، " + ("، ".join(parts) + "." if parts else "Evidence عملیاتی ثبت شده اما وضعیت سرویس/Process/Port به‌صورت کامل موجود نیست.")


def build_operator_summary(*, incident: Dict[str, Any], durable_evidence: Iterable[Dict[str, Any]], findings: Iterable[Dict[str, Any]], checkpoint: Dict[str, Any], approval: Optional[Dict[str, Any]] = None, audit_events: Optional[Iterable[Dict[str, Any]]] = None, memory_entry: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Deterministic, read-only operator Decision Support; never an execution authority."""
    state, finding_rows, audit = _d(checkpoint.get("state")), [dict(x) for x in findings if isinstance(x, dict)], [dict(x) for x in (audit_events or []) if isinstance(x, dict)]
    rows = _merge_evidence(state, durable_evidence, audit)
    observed, human = _observed(incident, state, rows), _human_action(rows)
    cause, confidence, cause_refs = _cause(observed, human, state, finding_rows)
    durable_approval, decision = _d(approval) or _d(state.get("approval")), _d(state.get("decision"))
    meta = _d(durable_approval.get("metadata"))
    approval_view = {"approval_id": _t(durable_approval.get("approval_id")) or None, "status": _low(durable_approval.get("status")) or "not_requested", "approver": meta.get("approved_by") or meta.get("rejected_by") or durable_approval.get("approver"), "risk_level": durable_approval.get("risk_level"), "action": durable_approval.get("action"), "binding_complete": _true(meta.get("binding_complete")), "tool": meta.get("tool_name"), "target": meta.get("target"), "runbook_id": meta.get("runbook_id"), "runbook_version": meta.get("runbook_version"), "environment": meta.get("environment")}
    request = _d(state.get("execution_request"))
    recommended = ({"tool": request.get("tool_name"), "action": request.get("action"), "target": request.get("target"), "parameters": _d(request.get("parameters")), "runbook_id": request.get("runbook_id"), "runbook_version": request.get("runbook_version"), "text_fa": " ".join(x for x in (_t(request.get("action")), "روی" if request.get("target") else "", _t(request.get("target"))) if x) or None} if request else ({"tool": None, "action": None, "target": None, "parameters": {}, "text_fa": _t(state.get("final_plan") or durable_approval.get("action"))} if _t(state.get("final_plan") or durable_approval.get("action")) else None))
    execution = _d(state.get("execution_result")); execution_status = "not_executed" if not execution else "blocked" if _true(execution.get("execution_blocked") or execution.get("blocked")) else "success" if _true(execution.get("success")) else "failed"
    execution_view = None if not execution else {"status": execution_status, "tool": execution.get("tool_name"), "action": execution.get("action"), "target": execution.get("target"), "reason": execution.get("reason"), "error": execution.get("error"), "result": execution.get("result"), "approval_id": execution.get("approval_id")}
    verification = _d(state.get("verification_result")); verification_status = _low(verification.get("status")) or ("not_recorded" if not verification else "unknown")
    verification_view = None if not verification else {"status": verification_status, "confidence": verification.get("confidence"), "message": verification.get("message"), "changes": _l(verification.get("changes")), "evidence_refs": _l(verification.get("evidence_refs")), "comparable_metrics": verification.get("comparable_metrics")}
    memory_status, memory = "not_recorded", None
    for event in audit:
        if _low(event.get("event_type")) == "memory_writeback":
            persisted = _true(_d(event.get("metadata")).get("persisted")); memory_status = "persisted" if persisted else "not_persisted"; memory = {"persisted": persisted, "verification_status": _d(event.get("metadata")).get("verification_status"), "memory_entry_id": _t(_d(memory_entry).get("id")) or None}; break
    if memory_entry and memory_status == "not_recorded": memory_status, memory = "persisted", {"persisted": True, "verification_status": memory_entry.get("verification_result"), "memory_entry_id": _t(memory_entry.get("id")) or None}
    risk = _low(decision.get("risk_level") or decision.get("risk") or durable_approval.get("risk_level")) or "unknown"
    preferred = set(cause_refs + list(human.get("evidence_ids") or [])); ranked = sorted(enumerate(rows), key=lambda x: (0 if _ref(x[1]) in preferred else 1, 0 if _low(_d(x[1].get("raw_data")).get("diagnostic")) in ({"service_status", "process_status", "port_listener_status", "tcp_check", "config_validate"} | DIRECT_LOG_DIAGNOSTICS) else 1, x[0]))
    key_evidence = [{"evidence_id": _ref(item), "source": item.get("source"), "type": item.get("type"), "diagnostic": _d(item.get("raw_data")).get("diagnostic"), "summary": _evidence_summary(item), "confidence": item.get("confidence")} for _, item in ranked[:12]]
    if approval_view["status"] == "pending": next_step = "شواهد و Execution Binding را بررسی کنید و درباره Approval تصمیم بگیرید؛ تا قبل از تأیید، عملیاتی اجرا نمی‌شود."
    elif approval_view["status"] == "approved" and execution_status == "not_executed": next_step = "در صورت تأیید نهایی هدف و Binding، workflow تأییدشده را Resume کنید؛ Approval هنگام شروع اجرا یک‌بار مصرف می‌شود."
    elif execution_status in {"failed", "blocked"}: next_step = "علت شکست یا Block شدن Execution را بررسی کنید و بدون Approval جدید، اجرای مجدد را فرض نکنید."
    elif execution_status == "success" and verification_status in {"not_recorded", "partial", "inconclusive", "unknown"}: next_step = "موفقیت Command را معادل Recovery ندانید؛ Verification عملیاتی را تکمیل کنید."
    elif verification_status in {"failed", "failure"}: next_step = "Recovery تأیید نشده است؛ شواهد پس از اجرا را بررسی و Incident را Escalate کنید."
    elif verification_status in {"success", "succeeded", "verified"} and memory_status == "not_persisted": next_step = "Recovery تأیید شده است؛ دلیل ذخیره‌نشدن نتیجه در Operational Memory را بررسی کنید."
    elif verification_status in {"success", "succeeded", "verified"}: next_step = "Recovery تأیید شده است؛ اثر باقی‌مانده را پایش و مطابق رویه Incident را ببندید."
    elif "مشخص نشده" in cause or "قابل تأیید نیست" in cause: next_step = "Evidence مستقیم بیشتری، به‌ویژه Journal/Audit و وضعیت فعلی سرویس، جمع‌آوری کنید."
    else: next_step = "شواهد و پیشنهاد AIOps را بازبینی کنید و فقط از مسیر Approval/Execution موجود تصمیم عملیاتی بگیرید."
    summary_parts = [_observed_text(observed), f"علت محتمل: {cause}"]
    if recommended and recommended.get("text_fa"): summary_parts.append(f"پیشنهاد AIOps: {recommended['text_fa']}.")
    summary_parts.append(f"Risk={risk}؛ Approval={approval_view['status']}" + (f"؛ Execution={execution_status}" if execution_status != "not_executed" else "") + (f"؛ Verification={verification_status}" if verification_status != "not_recorded" else "") + ".")
    return {
        "incident_id": _t(incident.get("id")) or None, "summary_fa": " ".join(summary_parts), "observed_state": observed,
        "likely_cause": cause, "cause_confidence": confidence, "cause_confidence_fa": CONFIDENCE_FA[confidence], "cause_evidence_ids": cause_refs,
        "human_action_indicator": human, "key_evidence": key_evidence, "recommended_action": recommended, "risk_level": risk,
        "analysis_basis": {"triage": _d(state.get("triage_result")) or None, "coordination": _d(state.get("coordination")) or None, "evaluation": _d(state.get("evaluation")) or None, "final_plan": _t(state.get("final_plan")) or None, "agent_findings": [{"agent": x.get("agent") or x.get("agent_name"), "finding_type": x.get("finding_type"), "statement": x.get("statement"), "evidence_ids": _l(x.get("evidence_ids")), "confidence": x.get("confidence")} for x in finding_rows[:20]]},
        "decision": decision or None, "approval_status": approval_view["status"], "approver": approval_view.get("approver"), "approval": approval_view,
        "execution_status": execution_status, "execution": execution_view, "verification_status": verification_status, "verification": verification_view,
        "memory_status": memory_status, "memory": memory, "operator_next_step": next_step,
        "source_policy": {"live_evidence_authoritative": True, "durable_state_only": True, "incident_context_is_fallback_only": True, "summary_is_decision_support": True, "execution_authority": False},
    }
