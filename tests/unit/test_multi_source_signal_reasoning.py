from __future__ import annotations

from datetime import datetime, timezone

import pytest

from apps.context_service.evidence_collector import EvidenceCollector
from apps.orchestrator.runtime import DurableWorkflowRuntime
from apps.orchestrator.signal_aware import SignalAwareE2EOrchestrator
from apps.security.rbac import allowed
from apps.signal_gateway import SignalGateway, signal_from_elasticsearch, signal_from_prometheus, signal_from_zabbix
from apps.signal_gateway.correlation import build_correlation_identity, signal_family
from integrations.base import LogEntry, MetricPoint


class EmptyZabbix:
    async def health_check(self):
        return True

    async def get_alerts(self, since=None, service=None, limit=100):
        return []


class ElasticLogs:
    async def health_check(self):
        return True

    async def get_logs(self, service, since, until=None, level=None, limit=100):
        return [LogEntry(
            timestamp=datetime.now(timezone.utc),
            service=service,
            level="error",
            message="database timeout anomaly",
            source="elasticsearch",
            raw_data={
                "service": {"name": service},
                "host": {"name": "pay-linux-01", "os": {"family": "linux"}},
                "message": "database timeout anomaly",
            },
        )]


class PromMetrics:
    async def health_check(self):
        return True

    async def get_metrics(self, service, metric_names, since, until=None):
        return [MetricPoint(
            timestamp=datetime.now(timezone.utc),
            service=service,
            name="cpu_usage",
            value=42.0,
            labels={"service": service, "instance": "pay-linux-01:9100"},
            source="prometheus",
        )]


@pytest.mark.asyncio
async def test_elk_trigger_can_be_correlated_when_zabbix_has_no_alert():
    collector = EvidenceCollector(
        zabbix=EmptyZabbix(),
        elasticsearch=ElasticLogs(),
        prometheus=PromMetrics(),
    )
    result = await collector.collect("payment-api", datetime.now(timezone.utc))
    evidence = result["evidence"]

    zabbix_observations = [
        item for item in evidence
        if item.get("type") == "source_observation" and item.get("source") == "zabbix"
    ]
    assert zabbix_observations
    assert zabbix_observations[0]["raw_data"]["status"] == "queried"
    assert zabbix_observations[0]["raw_data"]["result_count"] == 0
    assert any(item.get("type") == "log" and item.get("source") == "elasticsearch" for item in evidence)
    assert any(item.get("type") == "metric" and item.get("source") == "prometheus" for item in evidence)


def test_elasticsearch_anomaly_is_first_class_signal_and_evidence():
    signal = signal_from_elasticsearch({
        "_id": "elk-101",
        "_source": {
            "message": "ConnectionTimeout spike",
            "severity": "high",
            "service": {"name": "payment-api"},
            "host": {"name": "pay-linux-01", "os": {"family": "linux"}},
            "event": {"kind": "signal"},
        },
    })
    evidence = signal.to_evidence()
    assert signal.source == "elasticsearch"
    assert signal.service == "payment-api"
    assert evidence["type"] == "log"
    assert evidence["reference"] == "elk-101"
    assert evidence["raw_data"]["message"] == "ConnectionTimeout spike"


def test_prometheus_and_zabbix_can_also_initiate_incidents():
    prom = signal_from_prometheus({
        "fingerprint": "prom-1",
        "labels": {"alertname": "HighLatency", "service": "payment-api", "severity": "warning"},
        "annotations": {"summary": "latency elevated"},
    })
    zbx = signal_from_zabbix({
        "eventid": "z-1",
        "host": "vm-pay-01",
        "name": "High CPU",
        "severity": "high",
    })
    assert prom.source == "prometheus"
    assert prom.to_evidence()["type"] == "metric"
    assert zbx.source == "zabbix"
    assert zbx.service == "vm-pay-01"
    assert isinstance(zbx.raw_data["host"], dict)


def test_cross_source_error_signals_share_deterministic_fingerprint():
    asset = {
        "environment": "prod",
        "cluster": "core-k8s",
        "namespace": "payments",
        "workload_kind": "deployment",
        "workload": "payment-api",
    }
    elk = build_correlation_identity(
        service="payment-api",
        signal_type="signal",
        summary="ConnectionTimeout spike",
        asset=asset,
    )
    prom = build_correlation_identity(
        service="payment-api",
        signal_type="HighErrorRate",
        summary="HTTP errors elevated",
        asset=asset,
    )
    zabbix = build_correlation_identity(
        service="payment-api",
        signal_type="HTTP 500 rate high",
        summary="HTTP 500 rate high",
        asset=asset,
    )
    assert elk.signal_family == "service_error"
    assert elk.fingerprint == prom.fingerprint == zabbix.fingerprint


def test_correlation_refuses_unknown_family_or_unknown_service():
    assert signal_family("CustomBusinessEvent", "nothing operational") == "uncorrelated"
    unknown_family = build_correlation_identity(
        service="payment-api",
        signal_type="CustomBusinessEvent",
        summary="nothing operational",
    )
    unknown_service = build_correlation_identity(
        service="unknown",
        signal_type="HTTP 500",
        summary="500s elevated",
    )
    assert unknown_family.fingerprint is None
    assert unknown_service.fingerprint is None


def test_explicit_correlation_key_is_stable_and_not_plaintext():
    left = build_correlation_identity(
        service="payment-api",
        signal_type="anything",
        summary="anything",
        explicit_key="INCIDENT-123",
    )
    right = build_correlation_identity(
        service="payment-api",
        signal_type="different",
        summary="different",
        explicit_key="incident-123",
    )
    assert left.fingerprint == right.fingerprint
    assert "incident-123" not in str(left.fingerprint)


def test_append_trigger_to_checkpoint_is_idempotent():
    signal = signal_from_prometheus({
        "fingerprint": "prom-77",
        "labels": {"alertname": "HighErrorRate", "service": "payment-api"},
    })
    evidence = signal.to_evidence()
    state = {"context": {"trigger_evidence": [], "evidence": []}}
    SignalGateway._append_trigger_to_checkpoint(state, signal, evidence)
    SignalGateway._append_trigger_to_checkpoint(state, signal, evidence)
    assert len(state["context"]["trigger_evidence"]) == 1
    assert len(state["context"]["evidence"]) == 1


def test_peer_findings_are_published_as_auxiliary_operational_context():
    state = {"context": {"summary": {"log_count": 2}}}
    findings = [{"agent_name": "application", "evidence_ids": ["elk-101"], "confidence": 0.8}]
    coordination = {
        "confidence": 0.8,
        "agreement_score": 1.0,
        "disagreement": False,
        "contradictions": [],
        "consensus_hypotheses": ["database dependency degradation"],
        "missing_evidence": ["database metrics"],
        "evidence_requests": [{"evidence_type": "metric", "preferred_source": "prometheus"}],
        "handoff_agents": ["database"],
    }
    SignalAwareE2EOrchestrator._publish_peer_context(state, findings, coordination)
    peer = state["context"]["summary"]["peer_operational_context"]
    assert peer["policy"] == "peer_findings_are_auxiliary_context_not_live_evidence"
    assert peer["findings"][0]["agent_name"] == "application"
    assert peer["coordination"]["handoff_agents"] == ["database"]


def test_collaborative_orchestrator_is_durable_runtime_default():
    assert DurableWorkflowRuntime.__init__.__defaults__[0] is SignalAwareE2EOrchestrator


def test_signal_ingestion_is_not_viewer_permission():
    assert not allowed("viewer", "ingest:signal")
    assert allowed("operator", "ingest:signal")
    assert allowed("sre", "ingest:signal")
