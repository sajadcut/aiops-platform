from __future__ import annotations

from datetime import datetime, timezone

import pytest

from apps.context_service.evidence_collector import EvidenceCollector
from apps.orchestrator.runtime import DurableWorkflowRuntime
from apps.orchestrator.signal_aware import SignalAwareE2EOrchestrator
from apps.security.rbac import allowed
from apps.signal_gateway import signal_from_elasticsearch, signal_from_prometheus, signal_from_zabbix
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
