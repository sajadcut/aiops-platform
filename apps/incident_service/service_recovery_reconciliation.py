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


async def reconcile_after_applied_config(*, incident_id: str, target: str,
                                         service: str, actor: str) -> str:
    """Best-effort, fresh verification following an approved config + start.

    This is intentionally independent of the SSH apply result. A transient
    verification error must never convert a successful production apply into
    HTTP 500 or imply a Zabbix Recovery event.
    """
    import asyncio
    from datetime import datetime, timezone
    from uuid import UUID, uuid4
    from sqlalchemy import select
    from apps.approval_service.postgres import PostgreSQLApprovalStore
    from apps.audit_service.postgres import PostgreSQLAuditStore
    from database import AsyncSessionLocal
    from domain.models import Incident, IncidentStatus
    from integrations.vm.mcp_client import VMEdgeMCPClient

    try:
        client = VMEdgeMCPClient()
        first = await client.service_status(target, service)
        await asyncio.sleep(1.0)
        second = await client.service_status(target, service)
        vendor_ok = None
        if service.lower().removesuffix(".service") == "nginx":
            vendor = await client.config_validate(target, service)
            vendor_ok = (vendor.get("success") is True
                         and vendor.get("supported") is True
                         and vendor.get("valid") is True)
        async with AsyncSessionLocal() as db:
            incident = (await db.execute(
                select(Incident).where(Incident.id == UUID(incident_id)).with_for_update()
            )).scalar_one_or_none()
            if incident is None:
                return "incident_not_found"
            verdict = local_recovery_decision(
                source=str(incident.source or ""),
                summary=str(incident.summary or ""),
                service=str(incident.service or ""),
                context=incident.context or {},
                first=first, second=second, target=target,
                vendor_syntax_ok=vendor_ok,
            )
            if verdict != "independent_vm_verified":
                return verdict
            if incident.status in {IncidentStatus.CLOSED, IncidentStatus.RESOLVED}:
                return "incident_already_resolved"
            context = dict(incident.context or {})
            context["independent_recovery"] = {
                "source": "approved_config_apply_followup",
                "incident_resolved": True,
                "service": str(incident.service), "target": target,
                "monitor_recovered": False, "checks": 2,
                "nginx_vendor_validated": vendor_ok is True,
                "verified_at": datetime.now(timezone.utc).isoformat(),
            }
            incident.context = context
            incident.status = IncidentStatus.RESOLVED
            await db.commit()
            await PostgreSQLApprovalStore(db).cancel_unconsumed_for_incident(
                incident_id, reason="independent_vm_recovery_confirmed",
                metadata_patch={"recovery_source": "approved_config_apply_followup"},
            )
            await PostgreSQLAuditStore(db).append({
                "event_id": str(uuid4()), "event_type": "incident_independent_service_recovered",
                "actor": actor, "incident_id": incident_id,
                "action": "independent_service_recovery", "status": "verified",
                "metadata": {
                    "target": target, "service": service,
                    "systemd_observations": 2,
                    "monitor_recovered": False,
                    "vendor_validated": vendor_ok,
                    "recovery_source": "approved_config_apply_followup",
                    "execution_authority": False,
                },
                "created_at": datetime.now(timezone.utc).isoformat(),
            })
            return "resolved_independent_vm_verified"
    except Exception:
        from domain.contracts.logging import logger
        logger.warning("config_post_apply_recovery_reconciliation_unavailable",
                       incident_id=incident_id, service=service)
        return "recovery_verification_unavailable"
