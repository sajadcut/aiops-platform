import json

import pytest

from agents.messaging import MessagingAgent
from agents.messaging.engine import build_messaging_reliability_analysis
from agents.shared.base import AgentInput
from integrations.llm.base import LLMAdapter, LLMResponse


def metric(eid, ts, name, value, **raw):
    return {
        "id": eid,
        "type": "metric",
        "source": raw.pop("source", "prometheus"),
        "name": name,
        "value": value,
        "raw_data": {"timestamp": ts, **raw},
    }


def log(eid, ts, message, **raw):
    return {
        "id": eid,
        "type": "log",
        "source": raw.pop("source", "elasticsearch"),
        "message": message,
        "raw_data": {"timestamp": ts, **raw},
    }


def analyze(evidence):
    return build_messaging_reliability_analysis(evidence, service_name="orders", context={})


def causes(result):
    return {row["cause"]: row for row in result["cause_candidates"]}


def test_consumer_lag_uses_growth_trend_and_separates_slow_consumer():
    result = analyze([
        metric("broker", "2026-09-16T10:00:00Z", "broker_reachable", 1),
        metric("lag-1", "2026-09-16T10:00:00Z", "consumer_lag", 100, topic="orders", consumer_group="billing"),
        metric("lag-2", "2026-09-16T10:05:00Z", "consumer_lag", 400, topic="orders", consumer_group="billing"),
        metric("pub", "2026-09-16T10:05:00Z", "publish_rate", 100, topic="orders"),
        metric("con", "2026-09-16T10:05:00Z", "consume_rate", 40, topic="orders"),
    ])
    trend = result["lag_trends"][0]
    assert trend["delta"] == 300
    assert trend["derivative_per_second"] == pytest.approx(1.0)
    assert "slow_consumer" in causes(result)
    assert "broker_failure" not in causes(result)


def test_producer_spike_is_not_misclassified_as_broker_failure():
    result = analyze([
        metric("broker", "2026-09-16T11:00:00Z", "broker_reachable", 1),
        metric("pub", "2026-09-16T11:00:00Z", "publish_rate", 220, baseline=60, topic="orders"),
        metric("con", "2026-09-16T11:00:00Z", "consume_rate", 90, topic="orders"),
        metric("q1", "2026-09-16T10:55:00Z", "queue_depth", 10, topic="orders"),
        metric("q2", "2026-09-16T11:00:00Z", "queue_depth", 120, topic="orders"),
    ])
    assert "producer_surge" in causes(result)
    assert "broker_failure" not in causes(result)


def test_broker_unavailable_is_distinct_broker_failure():
    result = analyze([
        metric("broker-down", "2026-09-16T12:00:00Z", "broker_reachable", 0),
        log("controller", "2026-09-16T12:00:02Z", "controller unavailable"),
    ])
    candidate = causes(result)["broker_failure"]
    assert candidate["confidence"] >= 0.8
    assert "broker-down" in candidate["supporting_evidence_ids"]


def test_dlq_storm_with_retry_loop_is_poison_message_candidate():
    result = analyze([
        metric("broker", "2026-09-16T13:00:00Z", "broker_reachable", 1),
        metric("dlq-1", "2026-09-16T13:00:00Z", "dlq_depth", 0, topic="orders-dlq"),
        metric("dlq-2", "2026-09-16T13:05:00Z", "dlq_depth", 80, topic="orders-dlq"),
        metric("retry", "2026-09-16T13:05:00Z", "retry_rate", 25, topic="orders"),
        log("poison", "2026-09-16T13:04:00Z", "poison message repeatedly redelivered", topic="orders"),
    ])
    assert "poison_message_retry_loop" in causes(result)


def test_hot_partition_detects_throughput_skew():
    result = analyze([
        metric("p0", "2026-09-16T14:00:00Z", "partition_throughput", 300, topic="events", partition="0"),
        metric("p1", "2026-09-16T14:00:00Z", "partition_throughput", 50, topic="events", partition="1"),
        metric("p2", "2026-09-16T14:00:00Z", "partition_throughput", 50, topic="events", partition="2"),
    ])
    hot = result["partition_distribution"]["hot_partitions"]
    assert hot and hot[0]["partition"] == "0"
    assert "partition_skew" in causes(result)


def test_disk_induced_broker_latency_handoffs_to_infrastructure():
    result = analyze([
        metric("disk", "2026-09-16T15:00:00Z", "broker_disk_usage", 95),
        metric("await", "2026-09-16T15:00:00Z", "disk_latency_ms", 42),
        metric("broker", "2026-09-16T15:00:00Z", "broker_reachable", 1),
    ])
    assert "storage_pressure" in causes(result)
    assert any(row["agent"] == "infrastructure" for row in result["suggested_handoffs"])


def test_healthy_backlog_transient_is_not_broker_failure():
    result = analyze([
        metric("broker", "2026-09-16T16:00:00Z", "broker_reachable", 1),
        metric("q1", "2026-09-16T15:55:00Z", "queue_depth", 200, topic="orders"),
        metric("q2", "2026-09-16T16:00:00Z", "queue_depth", 80, topic="orders"),
        metric("l1", "2026-09-16T15:55:00Z", "consumer_lag", 50, topic="orders", consumer_group="billing"),
        metric("l2", "2026-09-16T16:00:00Z", "consumer_lag", 10, topic="orders", consumer_group="billing"),
    ])
    assert result["healthy_backlog_assessment"]["status"] == "healthy_transient_backlog"
    assert "broker_failure" not in causes(result)


class CapturingMessagingLLM(LLMAdapter):
    def __init__(self):
        self.prompt = ""

    @property
    def provider_name(self):
        return "messaging-capturing-test"

    async def generate(self, prompt, system_prompt=None, temperature=0.7, max_tokens=1000, **kwargs):
        self.prompt = prompt
        payload = {
            "severity": "medium",
            "health_status": "degraded",
            "findings": ["consumer lag growth requires application-side falsification"],
            "affected_components": ["orders-consumer"],
            "probable_dependencies": ["orders-topic"],
            "blast_radius": "orders async path",
            "hypotheses": [{
                "hypothesis": "slow consumer candidate",
                "probability": 0.95,
                "evidence_ids": ["lag-1", "lag-2"],
                "conflicting_evidence_ids": [],
                "falsification_checks": ["inspect handler latency"],
                "impacted_components": ["orders-consumer"],
                "recommended_next_evidence": ["consumer handler latency metric"],
            }],
            "missing_evidence": [],
            "handoff_agents": [],
            "immediate_checks": ["inspect consumer handler latency"],
            "confidence": 0.95,
        }
        return LLMResponse(content=json.dumps(payload), model="scenario")

    async def generate_with_messages(self, messages, temperature=0.7, max_tokens=1000, **kwargs):
        return await self.generate(messages[-1]["content"], temperature=temperature, max_tokens=max_tokens)


@pytest.mark.asyncio
async def test_messaging_agent_runs_deterministic_analysis_before_llm_and_remains_analysis_only():
    adapter = CapturingMessagingLLM()
    incident = AgentInput(
        incident_id="msg-1",
        service_name="orders-consumer",
        evidence_summary="lag increasing",
        context={"evidence": [
            {"id": "lag-1", "type": "metric", "source": "prometheus", "name": "consumer_lag", "value": 10, "raw_data": {"topic": "orders", "consumer_group": "billing", "baseline": 0}},
            {"id": "lag-2", "type": "metric", "source": "prometheus", "name": "consumer_lag", "value": 80, "raw_data": {"topic": "orders", "consumer_group": "billing", "baseline": 10}},
            {"id": "broker", "type": "metric", "source": "prometheus", "name": "broker_reachable", "value": 1},
        ]},
    )
    output = await MessagingAgent(adapter).analyze(incident)
    assert "MESSAGING_RELIABILITY_ANALYSIS=" in adapter.prompt
    assert output.analysis_details["messaging_analysis"]["policy"]
    assert output.analysis_details["execution_boundary"] == "analysis_only"
    assert output.confidence <= output.analysis_details["confidence_ceiling"]
    assert all(action.read_only for action in output.recommended_actions)
    assert {"application", "dependency", "network", "infrastructure"} <= set(MessagingAgent.spec.default_handoffs)
