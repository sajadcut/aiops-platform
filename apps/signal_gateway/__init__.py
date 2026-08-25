from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, Literal, Optional
from uuid import uuid4

from pydantic import BaseModel, Field, field_validator

from apps.context_service.asset_identity import AssetIdentityResolver
from apps.orchestrator.runtime import DurableWorkflowRuntime
from apps.orchestrator.signal_aware import SignalAwareE2EOrchestrator


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

    Any source may initiate an Incident. The initiating signal is retained as
    immutable seed Evidence, then the normal E2E workflow actively queries other
    configured evidence sources for corroboration. No LLM is used for signal
    normalization, asset identity, authentication, policy, approval or execution.
    """

    @staticmethod
    async def ingest(session, signal: OperationalSignal) -> Dict[str, Any]:
        trigger_evidence = signal.to_evidence()
        asset = AssetIdentityResolver.resolve([trigger_evidence], signal.service)
        resolved_service = str(asset.get("service") or signal.service or "unknown")
        incident_id = str(uuid4())
        correlation_key = signal.correlation_key or f"{resolved_service}:{signal.source}:{signal.source_id}"
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
        raw_data=raw,
    )
