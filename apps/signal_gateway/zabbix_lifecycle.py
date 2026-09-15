from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Dict, Optional
from uuid import UUID

from sqlalchemy import text

from apps.audit_service import AuditService
from apps.audit_service.postgres import PostgreSQLAuditStore
from apps.incident_service.repository import IncidentRepository
from apps.orchestrator.workflow_store import WorkflowCheckpointStore
from domain.contracts.logging import logger
from domain.models import Incident, IncidentStatus


_RECOVERY_STATES = {"recovery", "recovered", "resolved", "resolve", "ok", "closed"}


def _text_value(payload: Dict[str, Any], *keys: str) -> Optional[str]:
    for key in keys:
        value = payload.get(key)
        if value is None:
            continue
        text_value = str(value).strip()
        if text_value and text_value not in {"0.0.0.0"}:
            return text_value
    return None


def classify_zabbix_lifecycle(payload: Dict[str, Any]) -> Dict[str, Optional[str]]:
    """Return deterministic Problem/Recovery identity from the webhook payload.

    The generic ``value`` field is deliberately ignored because operational data
    can legitimately be ``0`` while the Zabbix event is still a PROBLEM. Use the
    explicit ``event_value`` field for {EVENT.VALUE} instead.
    """
    event_id = _text_value(payload, "eventid", "event_id", "id")
    recovery_id = _text_value(payload, "recovery_eventid", "recovery_event_id", "recovery_id")
    explicit_problem_id = _text_value(
        payload,
        "problem_eventid",
        "problem_event_id",
        "original_eventid",
        "original_event_id",
    )
    event_state = (_text_value(payload, "event_state", "event_status", "status") or "").lower()
    recovery_status = (_text_value(payload, "recovery_status") or "").lower()
    event_value = _text_value(payload, "event_value")

    is_recovery = bool(
        recovery_id
        or event_state in _RECOVERY_STATES
        or recovery_status in _RECOVERY_STATES
        or event_value == "0"
    )

    if not is_recovery:
        return {
            "state": "problem",
            "source_id": event_id,
            "problem_event_id": event_id,
            "recovery_event_id": None,
        }

    problem_event_id = explicit_problem_id or (event_id if recovery_id else None)
    recovery_event_id = recovery_id or (event_id if explicit_problem_id else None)
    return {
        "state": "recovery",
        "source_id": recovery_event_id,
        "problem_event_id": problem_event_id,
        "recovery_event_id": recovery_event_id,
    }


def _recovery_timestamp(payload: Dict[str, Any]) -> str:
    raw = _text_value(payload, "recovery_timestamp", "timestamp")
    if raw and raw.isdigit():
        try:
            return datetime.fromtimestamp(int(raw), tz=timezone.utc).isoformat()
        except (OverflowError, OSError, ValueError):
            pass
    return datetime.now(timezone.utc).isoformat()


def _recovery_evidence(payload: Dict[str, Any], identity: Dict[str, Optional[str]]) -> Dict[str, Any]:
    raw = dict(payload)
    raw["zabbix_lifecycle_state"] = "recovery"
    raw["problem_event_id"] = identity.get("problem_event_id")
    raw["recovery_event_id"] = identity.get("recovery_event_id")
    return {
        "type": "alert",
        "source": "zabbix",
        "reference": str(identity.get("recovery_event_id") or ""),
        "timestamp": _recovery_timestamp(payload),
        "confidence": 1.0,
        "raw_data": raw,
    }


async def _cancel_unconsumed_approvals(session, incident_id: str, recovery_event_id: str) -> list[str]:
    """Cancel stale write authority when the source reports recovery before execution."""
    patch = json.dumps(
        {
            "cancelled_due_to_source_recovery": True,
            "recovery_event_id": recovery_event_id,
        }
    )
    rows = (
        await session.execute(
            text(
                """
                UPDATE approvals
                SET status='rejected',
                    rejected_at=CURRENT_TIMESTAMP,
                    metadata=COALESCE(metadata, '{}'::jsonb) || CAST(:patch AS jsonb)
                WHERE incident_id=:incident_id
                  AND status IN ('pending', 'approved')
                RETURNING approval_id
                """
            ),
            {"incident_id": incident_id, "patch": patch},
        )
    ).scalars().all()
    return [str(value) for value in rows]


async def _record_source_recovery(
    session,
    *,
    incident_id: str,
    problem_event_id: str,
    recovery_event_id: str,
    payload: Dict[str, Any],
) -> Dict[str, Any]:
    incident = await session.get(Incident, UUID(str(incident_id)))
    if incident is None:
        raise ValueError("recovery_incident_not_found")

    context = dict(incident.context or {})
    related = [item for item in list(context.get("related_signals") or []) if isinstance(item, dict)]
    other_correlated_signals = [
        item
        for item in related
        if not (
            str(item.get("source") or "") == "zabbix"
            and str(item.get("source_id") or "") in {problem_event_id, recovery_event_id}
        )
    ]

    recovery = {
        "source": "zabbix",
        "problem_event_id": problem_event_id,
        "recovery_event_id": recovery_event_id,
        "recovered_at": _recovery_timestamp(payload),
        "summary": str(payload.get("recovery_name") or payload.get("name") or payload.get("message") or "Zabbix recovery"),
    }
    recoveries = [item for item in list(context.get("source_recoveries") or []) if isinstance(item, dict)]
    if recovery_event_id not in {str(item.get("recovery_event_id") or "") for item in recoveries}:
        recoveries.append(recovery)
    context["source_recoveries"] = recoveries[-100:]

    # A single-source Zabbix incident can be resolved by an authoritative Zabbix
    # recovery event. If other correlated signals exist, the source is recovered
    # but the incident remains open/analyzing until cross-source verification.
    incident_resolved = not other_correlated_signals
    recovery["incident_resolved"] = incident_resolved
    recovery["requires_cross_source_verification"] = bool(other_correlated_signals)
    context["source_recovery"] = recovery
    incident.context = context
    if incident_resolved and incident.status != IncidentStatus.CLOSED:
        incident.status = IncidentStatus.RESOLVED

    return {
        "incident_status": incident.status.value if isinstance(incident.status, IncidentStatus) else str(incident.status),
        "incident_resolved": incident_resolved,
        "requires_cross_source_verification": bool(other_correlated_signals),
        "correlated_signal_count": len(other_correlated_signals),
    }


async def _audit_recovery(
    session,
    *,
    incident_id: str,
    problem_event_id: str,
    recovery_event_id: str,
    outcome: Dict[str, Any],
    cancelled_approvals: list[str],
) -> None:
    AuditService.record(
        "verification_source_recovery_received",
        "zabbix_webhook",
        incident_id,
        "source_recovery",
        "verified" if outcome.get("incident_resolved") else "recorded",
        {
            "problem_event_id": problem_event_id,
            "recovery_event_id": recovery_event_id,
            "incident_resolved": bool(outcome.get("incident_resolved")),
            "requires_cross_source_verification": bool(outcome.get("requires_cross_source_verification")),
        },
    )
    if cancelled_approvals:
        AuditService.record(
            "approval_cancelled_on_source_recovery",
            "zabbix_webhook",
            incident_id,
            "cancel_stale_execution",
            "blocked",
            {
                "approval_ids": cancelled_approvals,
                "recovery_event_id": recovery_event_id,
            },
        )
    await AuditService.flush_to_store(PostgreSQLAuditStore(session), incident_id=incident_id)


async def ingest_zabbix_payload(session, payload: Dict[str, Any]) -> Dict[str, Any]:
    """Ingest a Zabbix Problem or Recovery without turning Recovery into a new Incident."""
    identity = classify_zabbix_lifecycle(payload)
    if identity["state"] == "problem":
        from apps.signal_gateway import SignalGateway, signal_from_zabbix

        result = await SignalGateway.ingest(session, signal_from_zabbix(payload))
        result["signal_state"] = "problem"
        result["recovered"] = False
        return result

    recovery_event_id = str(identity.get("recovery_event_id") or "")
    problem_event_id = str(identity.get("problem_event_id") or "")
    signal_type = str(payload.get("trigger") or payload.get("name") or "zabbix_recovery")

    if not recovery_event_id or not problem_event_id:
        logger.warning(
            "zabbix_recovery_parent_missing",
            recovery_event_id=recovery_event_id or None,
            has_problem_event_id=bool(problem_event_id),
        )
        return {
            "incident_id": None,
            "trigger_source": "zabbix",
            "trigger_signal_type": signal_type,
            "signal_state": "recovery",
            "recovered": False,
            "recovery_unmatched": True,
            "deduplicated": False,
            "terminal_reason": "zabbix_recovery_parent_event_missing",
        }

    incidents = IncidentRepository(session)
    checkpoints = WorkflowCheckpointStore(session)

    # Recovery retries are idempotent by their own recovery event ID.
    existing_recovery_incident = await incidents.find_incident_by_evidence_reference(
        source="zabbix", reference=recovery_event_id
    )
    if existing_recovery_incident:
        checkpoint = await checkpoints.load(existing_recovery_incident)
        state = dict((checkpoint or {}).get("state") or {})
        state.update(
            {
                "incident_id": existing_recovery_incident,
                "trigger_source": "zabbix",
                "trigger_signal_type": signal_type,
                "signal_state": "recovery",
                "recovered": True,
                "recovery_of_source_id": problem_event_id,
                "deduplicated": True,
                "deduplication_reason": "same_recovery_event_reference",
            }
        )
        return state

    await incidents.acquire_correlation_lock(f"zabbix-recovery:{problem_event_id}")

    # Re-check after lock to close concurrent webhook retry races.
    existing_recovery_incident = await incidents.find_incident_by_evidence_reference(
        source="zabbix", reference=recovery_event_id
    )
    if existing_recovery_incident:
        checkpoint = await checkpoints.load(existing_recovery_incident)
        state = dict((checkpoint or {}).get("state") or {})
        state.update(
            {
                "incident_id": existing_recovery_incident,
                "trigger_source": "zabbix",
                "trigger_signal_type": signal_type,
                "signal_state": "recovery",
                "recovered": True,
                "recovery_of_source_id": problem_event_id,
                "deduplicated": True,
                "deduplication_reason": "same_recovery_event_reference_after_lock",
            }
        )
        return state

    incident_id = await incidents.find_incident_by_evidence_reference(
        source="zabbix", reference=problem_event_id
    )
    if not incident_id:
        logger.warning(
            "zabbix_recovery_unmatched",
            problem_event_id=problem_event_id,
            recovery_event_id=recovery_event_id,
        )
        return {
            "incident_id": None,
            "trigger_source": "zabbix",
            "trigger_signal_type": signal_type,
            "signal_state": "recovery",
            "recovered": False,
            "recovery_unmatched": True,
            "recovery_of_source_id": problem_event_id,
            "deduplicated": False,
            "terminal_reason": "zabbix_recovery_problem_event_not_found",
        }

    evidence = _recovery_evidence(payload, identity)
    await incidents.add_evidence(incident_id, [evidence])
    outcome = await _record_source_recovery(
        session,
        incident_id=incident_id,
        problem_event_id=problem_event_id,
        recovery_event_id=recovery_event_id,
        payload=payload,
    )
    cancelled_approvals = await _cancel_unconsumed_approvals(
        session, incident_id, recovery_event_id
    )

    checkpoint = await checkpoints.load(incident_id)
    state = dict((checkpoint or {}).get("state") or {})
    context = state.setdefault("context", {})
    trigger_evidence = list(context.get("trigger_evidence") or [])
    if recovery_event_id not in {str(item.get("reference") or "") for item in trigger_evidence if isinstance(item, dict)}:
        trigger_evidence.append(evidence)
    context["trigger_evidence"] = trigger_evidence
    evidence_items = list(context.get("evidence") or [])
    if recovery_event_id not in {str(item.get("reference") or "") for item in evidence_items if isinstance(item, dict)}:
        evidence_items.append(evidence)
    context["evidence"] = evidence_items
    context["source_recovery"] = {
        "source": "zabbix",
        "problem_event_id": problem_event_id,
        "recovery_event_id": recovery_event_id,
        "incident_resolved": bool(outcome.get("incident_resolved")),
        "requires_cross_source_verification": bool(outcome.get("requires_cross_source_verification")),
    }

    state.update(
        {
            "incident_id": incident_id,
            "trigger_source": "zabbix",
            "trigger_signal_type": signal_type,
            "signal_state": "recovery",
            "recovered": True,
            "recovery_of_source_id": problem_event_id,
            "incident_status": outcome.get("incident_status"),
            "approval_cancellations": cancelled_approvals,
            "deduplicated": False,
            "correlated": True,
            "recovery_unmatched": False,
        }
    )
    if outcome.get("incident_resolved"):
        state["verification_result"] = {
            "status": "success",
            "method": "zabbix_source_recovery",
            "problem_event_id": problem_event_id,
            "recovery_event_id": recovery_event_id,
        }
        state["terminal_reason"] = "source_recovered"

    await _audit_recovery(
        session,
        incident_id=incident_id,
        problem_event_id=problem_event_id,
        recovery_event_id=recovery_event_id,
        outcome=outcome,
        cancelled_approvals=cancelled_approvals,
    )
    await incidents.commit()

    if checkpoint:
        await checkpoints.save(
            incident_id,
            state,
            status="completed" if outcome.get("incident_resolved") else str(checkpoint.get("status") or "paused"),
        )

    return state
