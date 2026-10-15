"""Conservative local recovery adjudication for systemd service-down incidents.

A read-only operator status check may legitimately establish that a service
is running. Resolution without a monitor RECOVERY is permitted only when the
original alert *specifically* asserts the same systemd service is down, the
bound VM/service has two fresh consistent observations and no other active
signal is correlated. Never label this as a Zabbix-origin recovery.
"""
from __future__ import annotations

import re
from typing import Any, Mapping


def is_service_down_alert(source: str, summary: str, service: str) -> bool:
    if str(source or "").lower() != "zabbix":
        return False
    name = str(service or "").strip().lower().removesuffix(".service")
    message = str(summary or "").lower()
    if not re.fullmatch(r"[a-z0-9@_.:-]{1,100}", name):
        return False
    return bool(re.search(r"(?<![a-z0-9_.-])" + re.escape(name)
                          + r"(?=[\s:,-])\s*(?:\S+\s+){0,2}?"
                          + r"(?:service\s+down|service\s+(?:stopped|failed)"
                          + r"|service\s+is\s+not\s+running)\b",
                          message))


def local_recovery_decision(*, source: str, summary: str, service: str,
                            context: Mapping[str, Any] | None,
                            first: Mapping[str, Any] | None,
                            second: Mapping[str, Any] | None,
                            target: str,
                            vendor_syntax_ok: bool | None = None) -> str:
    """Return a bounded status, not mutable Incident state."""
    ctx = context or {}
    if not is_service_down_alert(source, summary, service):
        return "alert_condition_unverified"
    related = ctx.get("related_signals") or []
    if not isinstance(related, list):
        return "correlation_unverified"
    if any(isinstance(x, dict) and str(x.get("source") or "").lower() != "zabbix"
           for x in related):
        return "other_correlated_signals"
    if len(related) > 1:
        return "other_correlated_signals"
    if (isinstance(ctx.get("source_recovery"), dict)
            and ctx["source_recovery"].get("incident_resolved") is True):
        return "source_already_recovered"
    name = str(service).lower().removesuffix(".service")
    for observation in (first, second):
        if not isinstance(observation, Mapping):
            return "second_check_unavailable"
        if (observation.get("success") is not True
                or observation.get("service", "").lower().removesuffix(".service") != name
                or observation.get("target") != target
                or observation.get("active_state") != "active"
                or observation.get("sub_state") != "running"):
            return "service_not_stably_running"
    if name == "nginx" and vendor_syntax_ok is not True:
        return "nginx_live_config_not_verified"
    return "independent_vm_verified"
