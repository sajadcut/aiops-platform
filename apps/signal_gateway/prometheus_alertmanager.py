from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from apps.approval_service.postgres import PostgreSQLApprovalStore
from apps.audit_service import AuditService
from apps.audit_service.postgres import PostgreSQLAuditStore
from apps.incident_service.repository import IncidentRepository
from apps.orchestrator.workflow_store import WorkflowCheckpointStore
from domain.contracts.config import settings
from domain.contracts.logging import logger
from domain.models import Incident, IncidentStatus


class AlertmanagerAlert(BaseModel):
    model_config = ConfigDict(extra="allow", populate_by_name=True)

    status: str = "firing"
    labels: Dict[str, str] = Field(default_factory=dict)
    annotations: Dict[str, str] = Field(default_factory=dict)
    starts_at: Any = Field(default=None, alias="startsAt")
    ends_at: Any = Field(default=None, alias="endsAt")
    generator_url: Optional[str] = Field(default=None, alias="generatorURL")
    fingerprint: Optional[str] = None


class AlertmanagerWebhookPayload(BaseModel):
    """Native Alertmanager generic-webhook v4 payload."""

    model_config = ConfigDict(extra="allow", populate_by_name=True)

    version: str = "4"
    group_key: str = Field(default="", alias="groupKey")
    truncated_alerts: int = Field(default=0, alias="truncatedAlerts", ge=0)
    status: str = "firing"
    receiver: str = ""
    group_labels: Dict[str, str] = Field(default_factory=dict, alias="groupLabels")
    common_labels: Dict[str, str] = Field(default_factory=dict, alias="commonLabels")
    common_annotations: Dict[str, str] = Field(default_factory=dict, alias="commonAnnotations")
    external_url: Optional[str] = Field(default=None, alias="externalURL")
    notification_reason: Optional[str] = None
    alerts: List[AlertmanagerAlert] = Field(default_factory=list)


def _text(value: Any) -> Optional[str]:
    text = str(value or "").strip()
    return text or None


def _timestamp(value: Any, *, fallback: Optional[datetime] = None) -> datetime:
    if isinstance(value, datetime):
        parsed = value
    else:
        text = _text(value)
        if not text:
            return fallback or datetime.now(timezone.utc)
        try:
            parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
        except ValueError:
            return fallback or datetime.now(timezone.utc)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _stable_hash(*parts: Any) -> str:
    material = "|".join(str(part or "").strip() for part in parts)
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def _alert_source_id(alert: Dict[str, Any]) -> str:
    direct = _text(alert.get("fingerprint"))
    if direct:
        return direct
    labels = alert.get("labels") if isinstance(alert.get("labels"), dict) else {}
    starts_at = _text(alert.get("startsAt") or alert.get("starts_at"))
    canonical_labels = json.dumps(labels, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return "prometheus-alert:" + _stable_hash(canonical_labels, starts_at)


def _service(labels: Dict[str, Any]) -> Optional[str]:
    preferred = settings.PROMETHEUS_MCP_SERVICE_LABEL.strip() or "service"
    for key in (preferred, "service", "service_name", "app", "application", "job"):
        value = _text(labels.get(key))
        if value:
            return value
    return None


def _status(alert: Dict[str, Any], envelope: Dict[str, Any]) -> str:
    return str(alert.get("status") or envelope.get("status") or "firing").strip().lower()


def _signal_from_alert(alert: Dict[str, Any], envelope: Dict[str, Any]):
    from apps.signal_gateway import OperationalSignal

    labels = dict(alert.get("labels") or {})
    annotations = dict(alert.get("annotations") or {})
    service = _service(labels)
    starts_at = _timestamp(alert.get("startsAt") or alert.get("starts_at"))
    group_context = {
        "version": envelope.get("version"),
        "groupKey": envelope.get("groupKey"),
        "receiver": envelope.get("receiver"),
        "groupLabels": envelope.get("groupLabels") or {},
        "commonLabels": envelope.get("commonLabels") or {},
        "externalURL": envelope.get("externalURL"),
        "notification_reason": envelope.get("notification_reason"),
    }
    raw_data = {
        "prometheus_alert_kind": "alertmanager",
        "alertmanager": group_context,
        "labels": labels,
        "annotations": annotations,
        "startsAt": starts_at.isoformat(),
        "endsAt": alert.get("endsAt") or alert.get("ends_at"),
        "generatorURL": alert.get("generatorURL") or alert.get("generator_url"),
        "fingerprint": _alert_source_id(alert),
    }
    return OperationalSignal(
        source="prometheus",
        source_id=_alert_source_id(alert),
        signal_type=str(labels.get("alertname") or "prometheus_alert"),
        severity=str(labels.get("severity") or "unknown"),
        summary=str(
            annotations.get("summary")
            or annotations.get("description")
            or labels.get("alertname")
            or "Prometheus alert"
        ),
        service=service,
        timestamp=starts_at,
        correlation_key=labels.get("correlation_key") or labels.get("incident_key"),
        raw_data=raw_data,
    )


def classify_alertmanager_alert(alert: Dict[str, Any], envelope: Dict[str, Any]) -> Dict[str, Optional[str]]:
    problem_event_id = _alert_source_id(alert)
    state = _status(alert, envelope)
    if state != "resolved":
        return {
            "state": "firing",
            "source_id": problem_event_id,
            "problem_event_id": problem_event_id,
            "recovery_event_id": None,
        }

    recovery_time = _text(alert.get("endsAt") or alert.get("ends_at"))
    if not recovery_time:
        recovery_time = _text(envelope.get("notification_reason")) or _text(envelope.get("groupKey")) or "resolved"
    recovery_event_id = "prometheus-recovery:" + _stable_hash(problem_event_id, recovery_time)
    return {
        "state": "resolved",
        "source_id": recovery_event_id,
        "problem_event_id": problem_event_id,
        "recovery_event_id": recovery_event_id,
    }


def _recovery_evidence(
    alert: Dict[str, Any],
    envelope: Dict[str, Any],
    identity: Dict[str, Optional[str]],
) -> Dict[str, Any]:
    labels = dict(alert.get("labels") or {})
    annotations = dict(alert.get("annotations") or {})
    resolved_at = _timestamp(alert.get("endsAt") or alert.get("ends_at"))
    return {
        "type": "alert",
        "source": "prometheus",
        "reference": str(identity.get("recovery_event_id") or ""),
        "timestamp": resolved_at.isoformat(),
        "confidence": 1.0,
        "raw_data": {
            "prometheus_alert_kind": "alertmanager_recovery",
            "labels": labels,
            "annotations": annotations,
            "startsAt": alert.get("startsAt") or alert.get("starts_at"),
            "endsAt": resolved_at.isoformat(),
            "generatorURL": alert.get("generatorURL") or alert.get("generator_url"),
            "fingerprint": identity.get("problem_event_id"),
            "problem_event_id": identity.get("problem_event_id"),
            "recovery_event_id": identity.get("recovery_event_id"),
            "alertmanager": {
                "version": envelope.get("version"),
                "groupKey": envelope.get("groupKey"),
                "receiver": envelope.get("receiver"),
                "notification_reason": envelope.get("notification_reason"),
            },
        },
    }


async def _record_source_recovery(
    session,
    *,
    incident_id: str,
    problem_event_id: str,
    recovery_event_id: str,
    alert: Dict[str, Any],
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
            str(item.get("source") or "") == "prometheus"
            and str(item.get("source_id") or "") in {problem_event_id, recovery_event_id}
        )
    ]

    annotations = alert.get("annotations") if isinstance(alert.get("annotations"), dict) else {}
    recovery = {
        "source": "prometheus",
        "problem_event_id": problem_event_id,
        "recovery_event_id": recovery_event_id,
        "recovered_at": _timestamp(alert.get("endsAt") or alert.get("ends_at")).isoformat(),
        "summary": str(
            annotations.get("summary")
            or annotations.get("description")
            or "Prometheus alert resolved"
        ),
    }
    recoveries = [item for item in list(context.get("source_recoveries") or []) if isinstance(item, dict)]
    if recovery_event_id not in {str(item.get("recovery_event_id") or "") for item in recoveries}:
        recoveries.append(recovery)
    context["source_recoveries"] = recoveries[-100:]

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
        "prometheus_alertmanager_webhook",
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
            "prometheus_alertmanager_webhook",
            incident_id,
            "cancel_stale_execution",
            "blocked",
            {
                "approval_ids": cancelled_approvals,
                "recovery_event_id": recovery_event_id,
            },
        )
    await AuditService.flush_to_store(PostgreSQLAuditStore(session), incident_id=incident_id)


async def _ingest_resolved_alert(
    session,
    *,
    alert: Dict[str, Any],
    envelope: Dict[str, Any],
    identity: Dict[str, Optional[str]],
) -> Dict[str, Any]:
    recovery_event_id = str(identity.get("recovery_event_id") or "")
    problem_event_id = str(identity.get("problem_event_id") or "")
    labels = alert.get("labels") if isinstance(alert.get("labels"), dict) else {}
    signal_type = str(labels.get("alertname") or "prometheus_alert")

    incidents = IncidentRepository(session)
    checkpoints = WorkflowCheckpointStore(session)

    existing_recovery_incident = await incidents.find_incident_by_evidence_reference(
        source="prometheus", reference=recovery_event_id
    )
    if existing_recovery_incident:
        checkpoint = await checkpoints.load(existing_recovery_incident)
        state = dict((checkpoint or {}).get("state") or {})
        state.update(
            {
                "incident_id": existing_recovery_incident,
                "trigger_source": "prometheus",
                "trigger_signal_type": signal_type,
                "signal_state": "resolved",
                "recovered": True,
                "recovery_of_source_id": problem_event_id,
                "deduplicated": True,
                "deduplication_reason": "same_recovery_event_reference",
            }
        )
        return state

    await incidents.acquire_correlation_lock(f"prometheus-recovery:{problem_event_id}")

    existing_recovery_incident = await incidents.find_incident_by_evidence_reference(
        source="prometheus", reference=recovery_event_id
    )
    if existing_recovery_incident:
        checkpoint = await checkpoints.load(existing_recovery_incident)
        state = dict((checkpoint or {}).get("state") or {})
        state.update(
            {
                "incident_id": existing_recovery_incident,
                "trigger_source": "prometheus",
                "trigger_signal_type": signal_type,
                "signal_state": "resolved",
                "recovered": True,
                "recovery_of_source_id": problem_event_id,
                "deduplicated": True,
                "deduplication_reason": "same_recovery_event_reference_after_lock",
            }
        )
        return state

    incident_id = await incidents.find_incident_by_evidence_reference(
        source="prometheus", reference=problem_event_id
    )
    if not incident_id:
        logger.warning(
            "prometheus_recovery_unmatched",
            problem_event_id=problem_event_id,
            recovery_event_id=recovery_event_id,
        )
        return {
            "incident_id": None,
            "trigger_source": "prometheus",
            "trigger_signal_type": signal_type,
            "signal_state": "resolved",
            "recovered": False,
            "recovery_unmatched": True,
            "recovery_of_source_id": problem_event_id,
            "deduplicated": False,
            "terminal_reason": "prometheus_recovery_problem_event_not_found",
        }

    evidence = _recovery_evidence(alert, envelope, identity)
    await incidents.add_evidence(incident_id, [evidence])
    outcome = await _record_source_recovery(
        session,
        incident_id=incident_id,
        problem_event_id=problem_event_id,
        recovery_event_id=recovery_event_id,
        alert=alert,
    )
    cancelled_approvals = await PostgreSQLApprovalStore(session).cancel_unconsumed_for_incident(
        incident_id,
        reason="prometheus_source_recovery",
        metadata_patch={
            "cancelled_due_to_source_recovery": True,
            "recovery_event_id": recovery_event_id,
        },
    )

    checkpoint = await checkpoints.load(incident_id)
    state = dict((checkpoint or {}).get("state") or {})
    context = state.setdefault("context", {})
    trigger_evidence = list(context.get("trigger_evidence") or [])
    if recovery_event_id not in {
        str(item.get("reference") or "") for item in trigger_evidence if isinstance(item, dict)
    }:
        trigger_evidence.append(evidence)
    context["trigger_evidence"] = trigger_evidence

    evidence_items = list(context.get("evidence") or [])
    if recovery_event_id not in {
        str(item.get("reference") or "") for item in evidence_items if isinstance(item, dict)
    }:
        evidence_items.append(evidence)
    context["evidence"] = evidence_items
    context["source_recovery"] = {
        "source": "prometheus",
        "problem_event_id": problem_event_id,
        "recovery_event_id": recovery_event_id,
        "incident_resolved": bool(outcome.get("incident_resolved")),
        "requires_cross_source_verification": bool(outcome.get("requires_cross_source_verification")),
    }

    state.update(
        {
            "incident_id": incident_id,
            "trigger_source": "prometheus",
            "trigger_signal_type": signal_type,
            "signal_state": "resolved",
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
            "method": "prometheus_alertmanager_source_recovery",
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


async def ingest_alertmanager_payload(session, payload: Dict[str, Any]) -> Dict[str, Any]:
    """Process every native Alertmanager webhook alert independently."""

    from apps.signal_gateway import SignalGateway

    raw_alerts = payload.get("alerts") if isinstance(payload.get("alerts"), list) else []
    truncated = int(payload.get("truncatedAlerts") or payload.get("truncated_alerts") or 0)
    if truncated:
        logger.warning(
            "alertmanager_webhook_truncated",
            truncated_alerts=truncated,
            group_key=payload.get("groupKey") or payload.get("group_key"),
        )

    results: List[Dict[str, Any]] = []
    firing_count = 0
    resolved_count = 0
    ignored_count = 0

    for raw_alert in raw_alerts:
        if not isinstance(raw_alert, dict):
            ignored_count += 1
            continue

        identity = classify_alertmanager_alert(raw_alert, payload)
        state = identity["state"]
        if state == "resolved":
            result = await _ingest_resolved_alert(
                session,
                alert=raw_alert,
                envelope=payload,
                identity=identity,
            )
            resolved_count += 1
        else:
            status = _status(raw_alert, payload)
            if status != "firing":
                ignored_count += 1
                results.append(
                    {
                        "status": "ignored",
                        "incident_id": None,
                        "trigger_source": "prometheus",
                        "trigger_signal_type": str((raw_alert.get("labels") or {}).get("alertname") or "prometheus_alert"),
                        "signal_state": status,
                        "ignored": True,
                        "deduplicated": False,
                        "terminal_reason": "unsupported_alertmanager_alert_status",
                    }
                )
                continue

            signal = _signal_from_alert(raw_alert, payload)
            result = await SignalGateway.ingest(session, signal)
            result.update(
                {
                    "signal_state": "firing",
                    "recovered": False,
                    "alert_fingerprint": signal.source_id,
                }
            )
            firing_count += 1
        results.append(result)

    return {
        "status": "accepted",
        "source": "prometheus",
        "transport": "alertmanager_webhook_v4",
        "group_key": payload.get("groupKey") or payload.get("group_key"),
        "receiver": payload.get("receiver"),
        "count": len(results),
        "firing_count": firing_count,
        "resolved_count": resolved_count,
        "ignored_count": ignored_count,
        "deduplicated_count": sum(1 for item in results if item.get("deduplicated")),
        "truncated_alerts": truncated,
        "partial": truncated > 0,
        "results": results,
    }
