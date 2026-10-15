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
    # Match only an explicit unit-down condition for this service.
    # An nginx port/latency/HTTP failure is not systemd service recovery.
    unit = r"(?<![a-z0-9_.-])" + re.escape(name) + r"(?:\.service)?(?![a-z0-9_.-])"
    terminal = r"(?:down|stopped|failed|not\s+running)"
    direct = (unit + r"\s*(?:[:,-]\s*)?"
              + r"(?:(?:systemd|unit)\s+)?(?:service\s+)?(?:is\s+)?"
              + terminal + r"\b")
    reversed_order = (r"(?<![a-z0-9_.-])service\s+" + unit
                      + r"\s*(?:is\s+)?" + terminal + r"\b")
    return bool(re.search(direct, message) or re.search(reversed_order, message))


def can_finalize_independent_recovery(roles: Any) -> bool:
    """Viewer access to incident status must never imply write authority."""
    from apps.security.rbac import allowed
    return bool(isinstance(roles, (tuple, list))
                and any(isinstance(role, str)
                        and allowed(role, "approve:low_risk")
                        for role in roles))


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
    related = ctx.get("related_signals", [])
    if not isinstance(related, list) or any(
        not isinstance(item, dict) for item in related
    ):
        return "correlation_unverified"
    # 'related_signals' records *other* correlated trigger events, not
    # proofs that our original source is healthy. Even a SINGLE Zabbix
    # sibling may still be firing, so do not close on a systemd observation.
    # If the original signal is duplicated here, the exact original
    # problem event ID must be available and match before ignoring it.
    trigger = ctx.get("trigger_signal") or {}
    trigger_payload = trigger.get("payload") or {} if isinstance(trigger, dict) else {}
    if not isinstance(trigger_payload, dict):
        trigger_payload = {}
    trigger_raw = trigger.get("raw_data") or {} if isinstance(trigger, dict) else {}
    if not isinstance(trigger_raw, dict):
        trigger_raw = {}
    original = str(
        trigger.get("source_id") or trigger.get("eventid")
        or trigger_payload.get("eventid") or trigger_payload.get("event_id")
        or trigger_raw.get("eventid") or trigger_raw.get("event_id") or ""
    ) if isinstance(trigger, dict) else ""
    other = [
        item for item in related
        if not (original
                and str(item.get("source") or "").lower() == "zabbix"
                and str(item.get("source_id") or "") == original)
    ]
    if other:
        return "other_correlated_signals"
    if (isinstance(ctx.get("source_recovery"), dict)
            and ctx["source_recovery"].get("incident_resolved") is True):
        return "source_already_recovered"
    name = str(service).lower().removesuffix(".service")
    for observation in (first, second):
        if not isinstance(observation, Mapping):
            return "second_check_unavailable"
        if (observation.get("success") is not True
                or str(observation.get("service") or "").lower().removesuffix(".service") != name
                or observation.get("target") != target
                or observation.get("active_state") != "active"
                or observation.get("sub_state") != "running"):
            return "service_not_stably_running"
    if name == "nginx" and vendor_syntax_ok is not True:
        return "nginx_live_config_not_verified"
    return "independent_vm_verified"


async def commit_independent_recovery(
    db, *, incident, target: str, actor: str,
    recovery_source: str, vendor_syntax_ok: bool | None,
) -> None:
    """Commit resolution, cancel stale Approvals and write Audit atomically.

    The caller must first lock the matching Incident row and independently
    verify both live observations. This helper never runs SSH or LLM commands.
    A failure rolls back all three mutations, preventing a RESOLVED incident
    with still-executable stale Approvals or missing provenance.
    """
    import json
    from datetime import datetime, timezone
    from uuid import uuid4
    from sqlalchemy import text
    from domain.models import IncidentStatus

    if recovery_source not in {"vm_mcp_systemd_recheck",
                               "approved_config_apply_followup"}:
        raise ValueError("untrusted_recovery_source")
    if incident.status in {IncidentStatus.CLOSED, IncidentStatus.RESOLVED}:
        raise ValueError("incident_already_terminal")
    context = dict(incident.context or {})
    context["independent_recovery"] = {
        "source": recovery_source,
        "incident_resolved": True,
        "verified_at": datetime.now(timezone.utc).isoformat(),
        "service": str(incident.service),
        "target": target,
        "monitor_recovered": False,
        "checks": 2,
        "nginx_vendor_validated": vendor_syntax_ok is True,
    }
    incident.context = context
    incident.status = IncidentStatus.RESOLVED
    await db.flush()
    patch = json.dumps({
        "cancellation_reason": "independent_vm_recovery_confirmed",
        "recovery_source": recovery_source,
    })
    cancelled = (await db.execute(text("""
        UPDATE approvals SET status='rejected', rejected_at=CURRENT_TIMESTAMP,
            metadata=COALESCE(metadata, '{}'::jsonb) ||
                     CAST(:metadata_patch AS jsonb)
        WHERE incident_id=:incident_id
          AND status IN ('pending_validation', 'pending', 'approved')
        RETURNING approval_id
    """), {"incident_id": str(incident.id), "metadata_patch": patch})).scalars().all()
    now = datetime.now(timezone.utc)
    metadata = {
        "target": target, "service": str(incident.service),
        "systemd_observations": 2, "monitor_recovered": False,
        "vendor_validated": vendor_syntax_ok,
        "recovery_source": recovery_source,
        "cancelled_approval_count": len(cancelled),
        "execution_authority": False,
    }
    await db.execute(text("""
        INSERT INTO audit_events
            (event_id,event_type,actor,incident_id,action,status,metadata,created_at)
        VALUES (:event_id,:event_type,:actor,:incident_id,:action,
                :status,CAST(:metadata AS jsonb),:created_at)
    """), {
        "event_id": str(uuid4()),
        "event_type": "incident_independent_service_recovered",
        "actor": actor, "incident_id": str(incident.id),
        "action": "independent_service_recovery", "status": "verified",
        "metadata": json.dumps(metadata), "created_at": now,
    })
    await db.commit()


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
            await commit_independent_recovery(
                db, incident=incident, target=target, actor=actor,
                recovery_source="approved_config_apply_followup",
                vendor_syntax_ok=vendor_ok,
            )
            return "resolved_independent_vm_verified"
    except Exception:
        from domain.contracts.logging import logger
        logger.warning("config_post_apply_recovery_reconciliation_unavailable",
                       incident_id=incident_id, service=service)
        return "recovery_verification_unavailable"
