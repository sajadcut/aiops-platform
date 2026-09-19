from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, Optional
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


_ACTIVE_STATES = {"active", "fired", "firing", "problem", "ongoing", "open"}
_RECOVERY_STATES = {"recovery", "recovered", "resolved", "resolve", "ok", "closed"}
_SERVICE_INFLUENCERS = {"service", "service.name", "service_name", "app", "application"}


class ElasticAnomalyWebhookPayload(BaseModel):
    """Versioned contract consumed by the Kibana ML anomaly webhook action.

    Rule/action variables can arrive as native JSON values or JSON-encoded
    strings depending on the Mustache template. Normalization handles both.
    """

    model_config = ConfigDict(extra="allow")

    schema_version: str = "1.0"
    source: str = "elastic"
    event_type: str = "ml_anomaly"
    state: str = "active"
    scheduled_at: Any = None
    service: Optional[str] = None
    correlation_key: Optional[str] = None
    rule: Dict[str, Any] = Field(default_factory=dict)
    alert: Dict[str, Any] = Field(default_factory=dict)
    anomaly: Dict[str, Any] = Field(default_factory=dict)


def _text(value: Any) -> Optional[str]:
    if value is None:
        return None
    text = str(value).strip()
    if not text or (text.startswith("{{") and text.endswith("}}")):
        return None
    return text


def _jsonish_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, tuple):
        return list(value)
    if isinstance(value, dict):
        return [value]
    text = _text(value)
    if not text:
        return []
    try:
        parsed = json.loads(text)
    except (TypeError, ValueError, json.JSONDecodeError):
        parsed = None
    if isinstance(parsed, list):
        return parsed
    if isinstance(parsed, dict):
        return [parsed]
    stripped = text.strip("[]")
    return [part.strip().strip('"').strip("'") for part in stripped.split(",") if part.strip()]


def _string_list(value: Any) -> list[str]:
    result: list[str] = []
    for item in _jsonish_list(value):
        text = _text(item)
        if text and text not in result:
            result.append(text)
    return result


def _object_list(value: Any) -> list[Dict[str, Any]]:
    return [dict(item) for item in _jsonish_list(value) if isinstance(item, dict)]


def _bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    return str(value or "").strip().lower() in {"1", "true", "yes", "y", "on"}


def _score(value: Any) -> Optional[float]:
    try:
        score = float(value)
    except (TypeError, ValueError):
        return None
    if score < 0:
        return 0.0
    if score > 100:
        return 100.0
    return score


def _timestamp(value: Any) -> Optional[datetime]:
    if value is None:
        return None
    if isinstance(value, datetime):
        parsed = value
    else:
        text = _text(value)
        if not text:
            return None
        try:
            numeric = float(text)
        except ValueError:
            numeric = None
        if numeric is not None:
            if numeric > 10_000_000_000:
                numeric /= 1000.0
            try:
                return datetime.fromtimestamp(numeric, tz=timezone.utc)
            except (OSError, OverflowError, ValueError):
                return None
        try:
            parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
        except ValueError:
            return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _stable_digest(*parts: Any) -> str:
    material = "|".join(str(part or "").strip() for part in parts)
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def _normalized_rule(payload: Dict[str, Any]) -> Dict[str, Any]:
    rule = payload.get("rule") if isinstance(payload.get("rule"), dict) else {}
    return {
        "id": _text(rule.get("id")),
        "name": _text(rule.get("name")),
        "space_id": _text(rule.get("space_id") or rule.get("spaceId")),
        "tags": _string_list(rule.get("tags")),
        "url": _text(rule.get("url")),
    }


def _normalized_alert(payload: Dict[str, Any]) -> Dict[str, Any]:
    alert = payload.get("alert") if isinstance(payload.get("alert"), dict) else {}
    return {
        "id": _text(alert.get("id")),
        "uuid": _text(alert.get("uuid")),
        "action_group": _text(alert.get("action_group") or alert.get("actionGroup")),
        "action_group_name": _text(alert.get("action_group_name") or alert.get("actionGroupName")),
        "action_subgroup": _text(alert.get("action_subgroup") or alert.get("actionSubgroup")),
        "consecutive_matches": alert.get("consecutive_matches") or alert.get("consecutiveMatches"),
        "flapping": alert.get("flapping"),
    }


def _normalized_anomaly(payload: Dict[str, Any]) -> Dict[str, Any]:
    anomaly = payload.get("anomaly") if isinstance(payload.get("anomaly"), dict) else {}
    return {
        "score": _score(anomaly.get("score")),
        "timestamp": _timestamp(
            anomaly.get("timestamp_iso8601")
            or anomaly.get("timestampIso8601")
            or anomaly.get("timestamp")
        ),
        "is_interim": _bool(anomaly.get("is_interim") if "is_interim" in anomaly else anomaly.get("isInterim")),
        "job_ids": _string_list(anomaly.get("job_ids") if "job_ids" in anomaly else anomaly.get("jobIds")),
        "message": _text(anomaly.get("message")),
        "anomaly_explorer_url": _text(anomaly.get("anomaly_explorer_url") or anomaly.get("anomalyExplorerUrl")),
        "top_influencers": _object_list(anomaly.get("top_influencers") if "top_influencers" in anomaly else anomaly.get("topInfluencers")),
        "top_records": _object_list(anomaly.get("top_records") if "top_records" in anomaly else anomaly.get("topRecords")),
    }


def normalize_elastic_anomaly_payload(payload: Dict[str, Any]) -> Dict[str, Any]:
    normalized = {
        "schema_version": _text(payload.get("schema_version")) or "1.0",
        "state": (_text(payload.get("state")) or "active").lower(),
        "scheduled_at": _timestamp(payload.get("scheduled_at") or payload.get("date")),
        "service": _text(payload.get("service")),
        "correlation_key": _text(payload.get("correlation_key")),
        "rule": _normalized_rule(payload),
        "alert": _normalized_alert(payload),
        "anomaly": _normalized_anomaly(payload),
    }
    return normalized


def _influencer_value(item: Dict[str, Any]) -> Optional[str]:
    raw = item.get("influencer_field_value")
    if raw is None:
        raw = item.get("influencerFieldValue")
    if isinstance(raw, list):
        for value in raw:
            text = _text(value)
            if text:
                return text
        return None
    return _text(raw)


def _influencer_name(item: Dict[str, Any]) -> str:
    return str(item.get("influencer_field_name") or item.get("influencerFieldName") or "").strip()


def _service_from_rule_tags(tags: Iterable[str]) -> Optional[str]:
    for tag in tags:
        text = str(tag or "").strip()
        lowered = text.lower()
        for prefix in ("service:", "service=", "service/"):
            if lowered.startswith(prefix):
                service = text[len(prefix):].strip()
                if service:
                    return service
    return None


def resolve_elastic_anomaly_service(normalized: Dict[str, Any]) -> Optional[str]:
    explicit = _text(normalized.get("service"))
    if explicit:
        return explicit

    anomaly = normalized.get("anomaly") or {}
    for item in anomaly.get("top_influencers") or []:
        if not isinstance(item, dict):
            continue
        if _influencer_name(item).lower() in _SERVICE_INFLUENCERS:
            value = _influencer_value(item)
            if value:
                return value

    rule = normalized.get("rule") or {}
    tagged = _service_from_rule_tags(rule.get("tags") or [])
    if tagged:
        return tagged

    for job_id in anomaly.get("job_ids") or []:
        mapped = settings.ELASTIC_ANOMALY_JOB_SERVICE_MAP.get(str(job_id))
        if mapped:
            return mapped
    return None


def _merge_path(target: Dict[str, Any], path: str, value: str) -> None:
    if path == "service.name":
        target.setdefault("service", {})["name"] = value
    elif path == "service.environment":
        target.setdefault("service", {})["environment"] = value
    elif path == "host.name":
        target.setdefault("host", {})["name"] = value
    elif path == "host.id":
        target.setdefault("host", {})["id"] = value
    elif path == "kubernetes.namespace":
        target.setdefault("kubernetes", {})["namespace"] = value
    elif path == "kubernetes.cluster.name":
        target.setdefault("kubernetes", {}).setdefault("cluster", {})["name"] = value
    elif path == "kubernetes.pod.name":
        target.setdefault("kubernetes", {}).setdefault("pod", {})["name"] = value
    elif path == "kubernetes.node.name":
        target.setdefault("kubernetes", {}).setdefault("node", {})["name"] = value


def _ecs_from_influencers(items: Iterable[Dict[str, Any]]) -> Dict[str, Any]:
    raw: Dict[str, Any] = {}
    supported = {
        "service.name", "service.environment", "host.name", "host.id",
        "kubernetes.namespace", "kubernetes.cluster.name",
        "kubernetes.pod.name", "kubernetes.node.name",
    }
    for item in items:
        if not isinstance(item, dict):
            continue
        name = _influencer_name(item)
        value = _influencer_value(item)
        if name in supported and value:
            _merge_path(raw, name, value)
    return raw


def _severity_from_score(score: Optional[float]) -> str:
    # Elastic UI bands: warning 0+, minor 25+, major 50+, critical 75+.
    # Map them into the platform's low/medium/high/critical vocabulary.
    if score is None:
        return "unknown"
    if score >= 75:
        return "critical"
    if score >= 50:
        return "high"
    if score >= 25:
        return "medium"
    return "low"


def _active_source_id(normalized: Dict[str, Any]) -> str:
    alert = normalized.get("alert") or {}
    direct = _text(alert.get("uuid")) or _text(alert.get("id"))
    if direct:
        return direct
    anomaly = normalized.get("anomaly") or {}
    rule = normalized.get("rule") or {}
    timestamp = anomaly.get("timestamp")
    digest = _stable_digest(
        rule.get("id"),
        ",".join(anomaly.get("job_ids") or []),
        timestamp.isoformat() if isinstance(timestamp, datetime) else timestamp,
        anomaly.get("score"),
        anomaly.get("message"),
    )
    return f"elastic-ml:{digest}"


def classify_elastic_anomaly_lifecycle(payload: Dict[str, Any]) -> Dict[str, Optional[str]]:
    normalized = normalize_elastic_anomaly_payload(payload)
    alert = normalized.get("alert") or {}
    state = str(normalized.get("state") or "active").lower()
    action_group = str(alert.get("action_group") or "").lower()
    is_recovery = state in _RECOVERY_STATES or "recover" in action_group

    problem_event_id = _active_source_id(normalized)
    if not is_recovery:
        return {
            "state": "active",
            "source_id": problem_event_id,
            "problem_event_id": problem_event_id,
            "recovery_event_id": None,
        }

    scheduled_at = normalized.get("scheduled_at")
    anomaly = normalized.get("anomaly") or {}
    recovery_material = (
        scheduled_at.isoformat() if isinstance(scheduled_at, datetime) else ""
    ) or (
        anomaly.get("timestamp").isoformat()
        if isinstance(anomaly.get("timestamp"), datetime)
        else ""
    )
    recovery_event_id = "elastic-ml-recovery:" + _stable_digest(
        problem_event_id,
        recovery_material,
        alert.get("action_group"),
        normalized.get("state"),
    )
    return {
        "state": "recovery",
        "source_id": recovery_event_id,
        "problem_event_id": problem_event_id,
        "recovery_event_id": recovery_event_id,
    }


def signal_from_elastic_anomaly(payload: Dict[str, Any]):
    from apps.signal_gateway import OperationalSignal

    normalized = normalize_elastic_anomaly_payload(payload)
    anomaly = normalized["anomaly"]
    service = resolve_elastic_anomaly_service(normalized)
    raw_data = _ecs_from_influencers(anomaly.get("top_influencers") or [])
    if service:
        raw_data.setdefault("service", {})["name"] = service
    raw_data.update(
        {
            "elastic_alert_kind": "ml_anomaly",
            "rule": normalized["rule"],
            "alert": normalized["alert"],
            "anomaly": {
                **anomaly,
                "timestamp": anomaly["timestamp"].isoformat() if isinstance(anomaly.get("timestamp"), datetime) else None,
            },
        }
    )

    first_record = next((item for item in anomaly.get("top_records") or [] if isinstance(item, dict)), {})
    function = _text(first_record.get("function"))
    field_name = _text(first_record.get("field_name") or first_record.get("fieldName"))
    signal_type_parts = ["ml_anomaly"] + [part for part in (function, field_name) if part]
    signal_type = ":".join(signal_type_parts)[:128]

    score = anomaly.get("score")
    jobs = anomaly.get("job_ids") or []
    record_hint = " ".join(part for part in (function, field_name) if part)
    summary = anomaly.get("message")
    if not summary:
        score_text = f"{score:g}" if isinstance(score, (int, float)) else "unknown"
        job_text = ",".join(jobs) if jobs else "unknown-job"
        summary = f"Elastic ML anomaly score {score_text} for {job_text}"
        if record_hint:
            summary += f" ({record_hint})"

    timestamp = anomaly.get("timestamp") or normalized.get("scheduled_at") or datetime.now(timezone.utc)
    return OperationalSignal(
        source="elasticsearch",
        source_id=_active_source_id(normalized),
        signal_type=signal_type,
        severity=_severity_from_score(score),
        summary=str(summary),
        service=service,
        timestamp=timestamp,
        correlation_key=normalized.get("correlation_key"),
        raw_data=raw_data,
    )


def _recovery_timestamp(normalized: Dict[str, Any]) -> str:
    value = normalized.get("scheduled_at")
    if isinstance(value, datetime):
        return value.isoformat()
    return datetime.now(timezone.utc).isoformat()


def _recovery_evidence(
    payload: Dict[str, Any],
    normalized: Dict[str, Any],
    identity: Dict[str, Optional[str]],
) -> Dict[str, Any]:
    anomaly = normalized.get("anomaly") or {}
    service = resolve_elastic_anomaly_service(normalized)
    raw = _ecs_from_influencers(anomaly.get("top_influencers") or [])
    if service:
        raw.setdefault("service", {})["name"] = service
    raw.update(
        {
            "elastic_alert_kind": "ml_anomaly_recovery",
            "rule": normalized.get("rule"),
            "alert": normalized.get("alert"),
            "anomaly": {
                **anomaly,
                "timestamp": anomaly["timestamp"].isoformat() if isinstance(anomaly.get("timestamp"), datetime) else None,
            },
            "problem_event_id": identity.get("problem_event_id"),
            "recovery_event_id": identity.get("recovery_event_id"),
        }
    )
    return {
        "type": "alert",
        "source": "elasticsearch",
        "reference": str(identity.get("recovery_event_id") or ""),
        "timestamp": _recovery_timestamp(normalized),
        "confidence": 1.0,
        "raw_data": raw,
    }


async def _record_source_recovery(
    session,
    *,
    incident_id: str,
    problem_event_id: str,
    recovery_event_id: str,
    normalized: Dict[str, Any],
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
            str(item.get("source") or "") == "elasticsearch"
            and str(item.get("source_id") or "") in {problem_event_id, recovery_event_id}
        )
    ]

    anomaly = normalized.get("anomaly") or {}
    recovery = {
        "source": "elasticsearch",
        "problem_event_id": problem_event_id,
        "recovery_event_id": recovery_event_id,
        "recovered_at": _recovery_timestamp(normalized),
        "summary": anomaly.get("message") or "Elastic ML anomaly recovered",
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
        "elasticsearch_webhook",
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
            "elasticsearch_webhook",
            incident_id,
            "cancel_stale_execution",
            "blocked",
            {
                "approval_ids": cancelled_approvals,
                "recovery_event_id": recovery_event_id,
            },
        )
    await AuditService.flush_to_store(PostgreSQLAuditStore(session), incident_id=incident_id)


async def ingest_elastic_anomaly_payload(session, payload: Dict[str, Any]) -> Dict[str, Any]:
    """Ingest Elastic ML anomaly active/recovery lifecycle events."""

    normalized = normalize_elastic_anomaly_payload(payload)
    anomaly = normalized.get("anomaly") or {}
    identity = classify_elastic_anomaly_lifecycle(payload)

    if identity["state"] == "active":
        if anomaly.get("is_interim") and not settings.ELASTIC_ANOMALY_ACCEPT_INTERIM:
            logger.info(
                "elastic_interim_anomaly_ignored",
                rule_id=(normalized.get("rule") or {}).get("id"),
                job_ids=anomaly.get("job_ids") or [],
                score=anomaly.get("score"),
            )
            return {
                "status": "ignored",
                "incident_id": None,
                "trigger_source": "elasticsearch",
                "trigger_signal_type": "ml_anomaly",
                "signal_state": "ignored",
                "ignored": True,
                "recovered": False,
                "deduplicated": False,
                "anomaly_score": anomaly.get("score"),
                "elastic_job_ids": anomaly.get("job_ids") or [],
                "terminal_reason": "elastic_interim_anomaly_ignored",
            }

        from apps.signal_gateway import SignalGateway

        result = await SignalGateway.ingest(session, signal_from_elastic_anomaly(payload))
        result.update(
            {
                "signal_state": "active",
                "recovered": False,
                "anomaly_score": anomaly.get("score"),
                "elastic_job_ids": anomaly.get("job_ids") or [],
            }
        )
        return result

    recovery_event_id = str(identity.get("recovery_event_id") or "")
    problem_event_id = str(identity.get("problem_event_id") or "")
    if not recovery_event_id or not problem_event_id:
        logger.warning("elastic_recovery_parent_missing")
        return {
            "incident_id": None,
            "trigger_source": "elasticsearch",
            "trigger_signal_type": "ml_anomaly",
            "signal_state": "recovery",
            "recovered": False,
            "recovery_unmatched": True,
            "deduplicated": False,
            "anomaly_score": anomaly.get("score"),
            "elastic_job_ids": anomaly.get("job_ids") or [],
            "terminal_reason": "elastic_recovery_parent_event_missing",
        }

    incidents = IncidentRepository(session)
    checkpoints = WorkflowCheckpointStore(session)

    existing_recovery_incident = await incidents.find_incident_by_evidence_reference(
        source="elasticsearch", reference=recovery_event_id
    )
    if existing_recovery_incident:
        checkpoint = await checkpoints.load(existing_recovery_incident)
        state = dict((checkpoint or {}).get("state") or {})
        state.update(
            {
                "incident_id": existing_recovery_incident,
                "trigger_source": "elasticsearch",
                "trigger_signal_type": "ml_anomaly",
                "signal_state": "recovery",
                "recovered": True,
                "recovery_of_source_id": problem_event_id,
                "deduplicated": True,
                "deduplication_reason": "same_recovery_event_reference",
                "anomaly_score": anomaly.get("score"),
                "elastic_job_ids": anomaly.get("job_ids") or [],
            }
        )
        return state

    await incidents.acquire_correlation_lock(f"elastic-recovery:{problem_event_id}")

    existing_recovery_incident = await incidents.find_incident_by_evidence_reference(
        source="elasticsearch", reference=recovery_event_id
    )
    if existing_recovery_incident:
        checkpoint = await checkpoints.load(existing_recovery_incident)
        state = dict((checkpoint or {}).get("state") or {})
        state.update(
            {
                "incident_id": existing_recovery_incident,
                "trigger_source": "elasticsearch",
                "trigger_signal_type": "ml_anomaly",
                "signal_state": "recovery",
                "recovered": True,
                "recovery_of_source_id": problem_event_id,
                "deduplicated": True,
                "deduplication_reason": "same_recovery_event_reference_after_lock",
                "anomaly_score": anomaly.get("score"),
                "elastic_job_ids": anomaly.get("job_ids") or [],
            }
        )
        return state

    incident_id = await incidents.find_incident_by_evidence_reference(
        source="elasticsearch", reference=problem_event_id
    )
    if not incident_id:
        logger.warning(
            "elastic_recovery_unmatched",
            problem_event_id=problem_event_id,
            recovery_event_id=recovery_event_id,
        )
        return {
            "incident_id": None,
            "trigger_source": "elasticsearch",
            "trigger_signal_type": "ml_anomaly",
            "signal_state": "recovery",
            "recovered": False,
            "recovery_unmatched": True,
            "recovery_of_source_id": problem_event_id,
            "deduplicated": False,
            "anomaly_score": anomaly.get("score"),
            "elastic_job_ids": anomaly.get("job_ids") or [],
            "terminal_reason": "elastic_recovery_problem_event_not_found",
        }

    evidence = _recovery_evidence(payload, normalized, identity)
    await incidents.add_evidence(incident_id, [evidence])
    outcome = await _record_source_recovery(
        session,
        incident_id=incident_id,
        problem_event_id=problem_event_id,
        recovery_event_id=recovery_event_id,
        normalized=normalized,
    )
    cancelled_approvals = await PostgreSQLApprovalStore(session).cancel_unconsumed_for_incident(
        incident_id,
        reason="elasticsearch_source_recovery",
        metadata_patch={
            "cancelled_due_to_source_recovery": True,
            "recovery_event_id": recovery_event_id,
        },
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
        "source": "elasticsearch",
        "problem_event_id": problem_event_id,
        "recovery_event_id": recovery_event_id,
        "incident_resolved": bool(outcome.get("incident_resolved")),
        "requires_cross_source_verification": bool(outcome.get("requires_cross_source_verification")),
    }

    state.update(
        {
            "incident_id": incident_id,
            "trigger_source": "elasticsearch",
            "trigger_signal_type": "ml_anomaly",
            "signal_state": "recovery",
            "recovered": True,
            "recovery_of_source_id": problem_event_id,
            "incident_status": outcome.get("incident_status"),
            "approval_cancellations": cancelled_approvals,
            "deduplicated": False,
            "correlated": True,
            "recovery_unmatched": False,
            "anomaly_score": anomaly.get("score"),
            "elastic_job_ids": anomaly.get("job_ids") or [],
        }
    )
    if outcome.get("incident_resolved"):
        state["verification_result"] = {
            "status": "success",
            "method": "elasticsearch_source_recovery",
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
