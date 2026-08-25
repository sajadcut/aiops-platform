from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Literal, Optional
from uuid import uuid4

from pydantic import BaseModel, Field, field_validator

from apps.context_service.asset_identity import AssetIdentityResolver
from apps.incident_service.repository import IncidentRepository
from apps.orchestrator.runtime import DurableWorkflowRuntime
from apps.orchestrator.signal_aware import SignalAwareE2EOrchestrator
from apps.orchestrator.workflow_store import WorkflowCheckpointStore
from apps.signal_gateway.correlation import build_correlation_identity
from domain.contracts.config import settings


SignalSource = Literal["zabbix", "elasticsearch", "prometheus", "kubernetes", "security", "manual"]


class OperationalSignal(BaseModel):
    source: SignalSource
    source_id: str = Field(min_length=1, max_length=512)
    signal_type: str = Field(min_length=1, max_length=128)
    severity: str = Field(default="unknown", max_length=64)
    summary: str = Field(min_length=1, max_length=4000)
    service: Optional[str] = Field(default=None, max_length=512)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    raw_data: Dict[str, Any] = Field(default_factory=dict)
    correlation_key: Optional[str] = Field(default=None, max_length=512)

    @field_validator("source", mode="before")
    @classmethod
    def normalize_source(cls, value: Any):
        source = str(value or "").strip().lower()
        aliases = {
            "elk": "elasticsearch",
            "elastic": "elasticsearch",
            "alertmanager": "prometheus",
            "prom": "prometheus",
            "k8s": "kubernetes",
        }
        return aliases.get(source, source)

    @field_validator("severity", mode="before")
    @classmethod
    def normalize_severity(cls, value: Any):
        severity = str(value or "unknown").strip().lower()
        aliases = {"disaster": "critical", "average": "medium", "warning": "medium", "information": "low"}
        return aliases.get(severity, severity)

    def to_evidence(self) -> Dict[str, Any]:
        evidence_type = "alert"
        kind = self.signal_type.lower()
        if self.source == "elasticsearch" or "log" in kind or "anomaly" in kind:
            evidence_type = "log" if self.source == "elasticsearch" else "event"
        elif self.source == "prometheus" or "metric" in kind:
            evidence_type = "metric"
        elif self.source == "kubernetes":
            evidence_type = "event"
        return {
            "type": evidence_type,
            "source": self.source,
            "reference": self.source_id,
            "timestamp": self.timestamp.isoformat(),
            "confidence": 1.0,
            "raw_data": {
                **self.raw_data,
                "signal_type": self.signal_type,
                "signal_summary": self.summary,
                "signal_severity": self.severity,
                "service": self.service or self.raw_data.get("service"),
            },
        }


class SignalGateway:
    """Source-agnostic entry point for operational anomalies and alerts.

    Any source may initiate an Incident. Exact source-event retries are
    idempotent. Cross-source correlation is deterministic and bounded by stable
    service/workload identity, a conservative signal family and a short time
    window. LLM/free-text similarity is never merge authority.
    """

    @staticmethod
    def _append_trigger_to_checkpoint(state: Dict[str, Any], signal: OperationalSignal, evidence: Dict[str, Any]) -> None:
        context = state.setdefault("context", {})
        triggers = list(context.get("trigger_evidence") or [])
        if not any(
            str(item.get("source")) == signal.source and str(item.get("reference")) == signal.source_id
            for item in triggers if isinstance(item, dict)
        ):
            triggers.append(evidence)
        context["trigger_evidence"] = triggers
        evidence_items = list(context.get("evidence") or [])
        if not any(
            str(item.get("source")) == signal.source and str(item.get("reference")) == signal.source_id
            for item in evidence_items if isinstance(item, dict)
        ):
            evidence_items.append(evidence)
        context["evidence"] = evidence_items

    @staticmethod
    async def ingest(session, signal: OperationalSignal) -> Dict[str, Any]:
        trigger_evidence = signal.to_evidence()
        asset = AssetIdentityResolver.resolve([trigger_evidence], signal.service)
        resolved_service = str(asset.get("service") or signal.service or "unknown")
        correlation = build_correlation_identity(
            service=resolved_service,
            signal_type=signal.signal_type,
            summary=signal.summary,
            asset=asset,
            explicit_key=signal.correlation_key,
        )
        correlation_key = signal.correlation_key or correlation.fingerprint or f"{resolved_service}:{signal.source}:{signal.source_id}"

        incidents = IncidentRepository(session)
        checkpoints = WorkflowCheckpointStore(session)

        # Exact retry idempotency always wins and requires no fuzzy/cross-source logic.
        existing_incident_id = await incidents.find_incident_by_evidence_reference(
            source=signal.source,
            reference=signal.source_id,
        )
        if existing_incident_id:
            checkpoint = await checkpoints.load(existing_incident_id)
            existing_state = dict((checkpoint or {}).get("state") or {})
            existing_state["incident_id"] = existing_incident_id
            existing_state["trigger_source"] = signal.source
            existing_state["trigger_signal_type"] = signal.signal_type
            existing_state["correlation_key"] = correlation_key
            existing_state["deduplicated"] = True
            existing_state["deduplication_reason"] = "same_source_event_reference"
            existing_state["correlated"] = False
            return existing_state

        if settings.SIGNAL_CORRELATION_ENABLED and correlation.fingerprint:
            # Transaction-scoped PostgreSQL advisory lock closes the concurrent
            # webhook race for one fingerprint. Recheck exact idempotency after
            # acquiring it because another request may have committed meanwhile.
            await incidents.acquire_correlation_lock(correlation.fingerprint)
            existing_incident_id = await incidents.find_incident_by_evidence_reference(
                source=signal.source,
                reference=signal.source_id,
            )
            if not existing_incident_id:
                existing_incident_id = await incidents.find_correlated_open_incident(
                    fingerprint=correlation.fingerprint,
                    service=resolved_service,
                    since=signal.timestamp - timedelta(seconds=settings.SIGNAL_CORRELATION_WINDOW_SECONDS),
                    limit=settings.SIGNAL_CORRELATION_CANDIDATE_LIMIT,
                )
            if existing_incident_id:
                signal_metadata = {
                    "source": signal.source,
                    "source_id": signal.source_id,
                    "signal_type": signal.signal_type,
                    "severity": signal.severity,
                    "timestamp": signal.timestamp.isoformat(),
                    "correlation_fingerprint": correlation.fingerprint,
                    "signal_family": correlation.signal_family,
                }
                await incidents.attach_correlated_signal(
                    existing_incident_id,
                    evidence=trigger_evidence,
                    signal_metadata=signal_metadata,
                )
                checkpoint = await checkpoints.load(existing_incident_id)
                existing_state = dict((checkpoint or {}).get("state") or {})
                if existing_state:
                    SignalGateway._append_trigger_to_checkpoint(existing_state, signal, trigger_evidence)
                    existing_state["correlated_signals"] = list(
                        (existing_state.get("correlated_signals") or []) + [signal_metadata]
                    )[-100:]
                    await checkpoints.save(
                        existing_incident_id,
                        existing_state,
                        status=str((checkpoint or {}).get("status") or "paused"),
                    )
                else:
                    await incidents.commit()
                existing_state["incident_id"] = existing_incident_id
                existing_state["trigger_source"] = signal.source
                existing_state["trigger_signal_type"] = signal.signal_type
                existing_state["correlation_key"] = correlation_key
                existing_state["deduplicated"] = True
                existing_state["deduplication_reason"] = "cross_source_correlation"
                existing_state["correlated"] = True
                existing_state["correlation_fingerprint"] = correlation.fingerprint
                return existing_state

        incident_id = str(uuid4())
        correlation_context = {
            "fingerprint": correlation.fingerprint,
            "signal_family": correlation.signal_family,
            "scope": correlation.scope,
            "explicit": correlation.explicit,
            "window_seconds": settings.SIGNAL_CORRELATION_WINDOW_SECONDS,
        }
        incident_context = {
            "source": signal.source,
            "severity": signal.severity,
            "service": resolved_service,
            "summary": signal.summary,
            "signal_type": signal.signal_type,
            "correlation_key": correlation_key,
        }
        initial_state = {
            "incident_id": incident_id,
            "service_name": resolved_service,
            "evidence_summary": f"Trigger source={signal.source}; type={signal.signal_type}; severity={signal.severity}; {signal.summary}",
            "context": {
                "incident": incident_context,
                "service": resolved_service,
                "asset_context": asset,
                "correlation": correlation_context,
                "related_signals": [],
                "trigger_signal": signal.model_dump(mode="json"),
                "trigger_evidence": [trigger_evidence],
                "evidence": [trigger_evidence],
            },
            "messages": [],
            "findings": [],
            "confidence": 0.0,
        }
        result = await DurableWorkflowRuntime(
            session,
            orchestrator_cls=SignalAwareE2EOrchestrator,
        ).start(initial_state)
        result["trigger_source"] = signal.source
        result["trigger_signal_type"] = signal.signal_type
        result["correlation_key"] = correlation_key
        result["correlation_fingerprint"] = correlation.fingerprint
        result["deduplicated"] = False
        result["correlated"] = False
        return result


def signal_from_elasticsearch(payload: Dict[str, Any]) -> OperationalSignal:
    source = payload.get("_source") if isinstance(payload.get("_source"), dict) else payload
    service = source.get("service")
    if isinstance(service, dict):
        service = service.get("name")
    rule = source.get("rule") if isinstance(source.get("rule"), dict) else {}
    event = source.get("event") if isinstance(source.get("event"), dict) else {}
    return OperationalSignal(
        source="elasticsearch",
        source_id=str(payload.get("_id") or source.get("id") or event.get("id") or uuid4()),
        signal_type=str(event.get("kind") or event.get("action") or rule.get("category") or "log_anomaly"),
        severity=str(source.get("severity") or rule.get("severity") or "unknown"),
        summary=str(source.get("message") or rule.get("name") or "Elasticsearch anomaly detected"),
        service=str(service) if service else None,
        correlation_key=source.get("correlation_key") or event.get("correlation_key"),
        raw_data=source,
    )


def signal_from_prometheus(payload: Dict[str, Any]) -> OperationalSignal:
    labels = payload.get("labels") or {}
    annotations = payload.get("annotations") or {}
    return OperationalSignal(
        source="prometheus",
        source_id=str(payload.get("fingerprint") or labels.get("alertname") or uuid4()),
        signal_type=str(labels.get("alertname") or "metric_alert"),
        severity=str(labels.get("severity") or "unknown"),
        summary=str(annotations.get("summary") or annotations.get("description") or labels.get("alertname") or "Prometheus alert"),
        service=labels.get("service") or labels.get("service_name") or labels.get("app"),
        correlation_key=labels.get("correlation_key") or labels.get("incident_key"),
        raw_data={"labels": labels, "annotations": annotations, **{k: v for k, v in payload.items() if k not in {"labels", "annotations"}}},
    )


def signal_from_zabbix(payload: Dict[str, Any]) -> OperationalSignal:
    raw = dict(payload)
    host_value = payload.get("host") or payload.get("hostname")
    if host_value and not isinstance(host_value, dict):
        raw["host"] = {"host": str(host_value), "name": str(host_value)}
    service = payload.get("service") or host_value
    return OperationalSignal(
        source="zabbix",
        source_id=str(payload.get("eventid") or payload.get("event_id") or payload.get("id") or uuid4()),
        signal_type=str(payload.get("trigger") or payload.get("name") or "zabbix_problem"),
        severity=str(payload.get("severity") or "unknown"),
        summary=str(payload.get("name") or payload.get("message") or "Zabbix problem detected"),
        service=str(service) if service else None,
        correlation_key=payload.get("correlation_key") or payload.get("incident_key"),
        raw_data=raw,
    )
