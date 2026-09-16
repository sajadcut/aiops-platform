import json

import pytest

from agents.change import ChangeAgent
from agents.change.engine import build_change_correlation_analysis
from agents.shared.base import AgentInput
from integrations.llm.base import LLMAdapter, LLMResponse


def change(eid, ts, change_type="deployment", **raw):
    return {
        "id": eid,
        "type": "change",
        "source": "change-control",
        "timestamp": ts,
        "raw_data": {"change_type": change_type, **raw},
    }


def metric(eid, ts, name, value, **raw):
    return {
        "id": eid,
        "type": "metric",
        "source": "prometheus",
        "timestamp": ts,
        "name": name,
        "value": value,
        "raw_data": raw,
    }


def log(eid, ts, message, **raw):
    return {
        "id": eid,
        "type": "log",
        "source": "elasticsearch",
        "timestamp": ts,
        "message": message,
        "raw_data": raw,
    }


def analyze(evidence, **context):
    return build_change_correlation_analysis(
        evidence,
        service_name="payments",
        context={
            "incident_start": "2026-09-16T10:05:00Z",
            "time_range": {"start": "2026-09-16T10:05:00Z", "end": "2026-09-16T10:30:00Z"},
            **context,
        },
    )


def top(result):
    return result["candidate_changes"][0]


def test_bad_deployment_gets_high_score_from_delta_scope_and_stable_comparison():
    result = analyze([
        change("deploy-v2", "2026-09-16T10:00:00Z", version="v2", service="payments", target="payments-api", build_result="success"),
        metric("before-err", "2026-09-16T09:58:00Z", "http_error_rate", 0.01, service="payments", version="v1"),
        metric("after-v2-err", "2026-09-16T10:03:00Z", "http_error_rate", 0.30, service="payments", version="v2", role="canary"),
        metric("after-v1-err", "2026-09-16T10:03:00Z", "http_error_rate", 0.01, service="payments", version="v1", role="stable"),
        metric("before-lat", "2026-09-16T09:58:00Z", "request_latency_ms", 100, service="payments", version="v1"),
        metric("after-v2-lat", "2026-09-16T10:03:00Z", "request_latency_ms", 900, service="payments", version="v2", role="canary"),
        metric("after-v1-lat", "2026-09-16T10:03:00Z", "request_latency_ms", 105, service="payments", version="v1", role="stable"),
    ])
    candidate = top(result)
    assert candidate["change_id"] == "deploy-v2"
    assert candidate["change_correlation_score"] >= 0.70
    assert candidate["score_factors"]["metric_log_delta"] > 0
    assert candidate["score_factors"]["affected_scope_overlap"] > 0.5
    assert candidate["score_factors"]["reproducibility_instance_comparison"] > 0.5
    assert result["rollback_candidate_evidence"]
    assert result["rollback_candidate_evidence"][0]["policy"] == "rollback_candidate_only_never_execute_without_approval"


def test_unrelated_deployment_is_not_promoted_by_temporal_fact_alone():
    result = analyze([
        change("deploy-other", "2026-09-16T07:00:00Z", version="v7", service="catalog", target="catalog-api", build_result="success"),
        metric("pay-before", "2026-09-16T09:58:00Z", "http_error_rate", 0.01, service="payments"),
        metric("pay-after", "2026-09-16T10:06:00Z", "http_error_rate", 0.01, service="payments"),
    ])
    candidate = top(result)
    assert candidate["change_correlation_score"] < 0.35
    assert candidate["causal_role"] == "weak_or_unrelated_change"
    assert "no_measured_before_after_delta" in candidate["conflicting_evidence"]
    assert candidate["score_factors"]["temporal_proximity"] <= 0.2
    assert not result["rollback_candidate_evidence"]


def test_config_drift_on_affected_subset_is_a_change_candidate():
    result = analyze([
        change("cfg-a", "2026-09-16T10:01:00Z", "config", service="payments", target="pod-a", config_hash="hash-b"),
        metric("before", "2026-09-16T09:59:00Z", "http_error_rate", 0.01, service="payments", instance="pod-a"),
        metric("pod-a", "2026-09-16T10:04:00Z", "http_error_rate", 0.22, service="payments", instance="pod-a", role="canary"),
        metric("pod-b", "2026-09-16T10:04:00Z", "http_error_rate", 0.01, service="payments", instance="pod-b", role="stable"),
    ])
    candidate = top(result)
    assert candidate["change_type"] == "config"
    assert candidate["config_hash"] == "hash-b"
    assert candidate["change_correlation_score"] >= 0.60
    assert candidate["scope_overlap"]


def test_dependency_outage_simultaneous_with_deploy_weakens_change_causality():
    result = analyze([
        change("deploy-v2", "2026-09-16T10:00:00Z", version="v2", service="payments", build_result="success"),
        metric("before", "2026-09-16T09:58:00Z", "http_error_rate", 0.01, service="payments", version="v1"),
        metric("new", "2026-09-16T10:04:00Z", "http_error_rate", 0.30, service="payments", version="v2", role="canary"),
        metric("stable", "2026-09-16T10:04:00Z", "http_error_rate", 0.29, service="payments", version="v1", role="stable"),
        log("dep", "2026-09-16T10:02:00Z", "upstream dependency outage: checkout-provider unavailable", service="payments"),
    ])
    candidate = top(result)
    assert any(row["cause"] == "dependency_outage" for row in result["alternative_causes"])
    assert candidate["instance_version_comparison"]["all_versions_similarly_affected"] is True
    assert "stable_and_new_versions_are_similarly_affected" in candidate["conflicting_evidence"]
    assert candidate["change_correlation_score"] < 0.70


def test_partial_canary_regression_increases_confidence_over_stable_replicas():
    result = analyze([
        change("canary-v3", "2026-09-16T10:00:00Z", "kubernetes_rollout", version="v3", service="payments", target="payments", rollout_status="progressing"),
        metric("before", "2026-09-16T09:59:00Z", "request_latency_ms", 100, service="payments", version="v2"),
        metric("canary", "2026-09-16T10:03:00Z", "request_latency_ms", 1000, service="payments", version="v3", role="canary"),
        metric("stable", "2026-09-16T10:03:00Z", "request_latency_ms", 105, service="payments", version="v2", role="stable"),
    ])
    candidate = top(result)
    comparison = candidate["instance_version_comparison"]["comparisons"][0]
    assert comparison["relative_degradation"] > 1
    assert candidate["score_factors"]["baseline_canary_comparison"] > 0.5
    assert candidate["change_correlation_score"] >= 0.65


class CapturingChangeLLM(LLMAdapter):
    def __init__(self):
        self.prompt = ""

    @property
    def provider_name(self):
        return "change-capturing-test"

    async def generate(self, prompt, system_prompt=None, temperature=0.7, max_tokens=1000, **kwargs):
        self.prompt = prompt
        payload = {
            "severity": "high",
            "health_status": "degraded",
            "findings": ["new canary version regresses while stable remains healthy"],
            "affected_components": ["payments"],
            "probable_dependencies": [],
            "blast_radius": "canary subset",
            "hypotheses": [{
                "hypothesis": "v3 rollout is a causal regression candidate",
                "probability": 0.8,
                "evidence_ids": ["canary-v3", "canary", "stable"],
                "conflicting_evidence_ids": [],
                "falsification_checks": ["compare the same endpoint on stable replicas"],
                "impacted_components": ["payments"],
                "recommended_next_evidence": ["per-version error and latency"],
            }],
            "missing_evidence": [],
            "handoff_agents": ["application", "kubernetes"],
            "immediate_checks": ["Inspect per-version error and latency for canary and stable replicas"],
            "confidence": 0.8,
        }
        return LLMResponse(content=json.dumps(payload), model="scenario")

    async def generate_with_messages(self, messages, temperature=0.7, max_tokens=1000, **kwargs):
        return await self.generate(messages[-1]["content"], temperature=temperature, max_tokens=max_tokens)


@pytest.mark.asyncio
async def test_change_agent_exposes_required_outputs_and_never_executes_rollback():
    adapter = CapturingChangeLLM()
    evidence = [
        {
            "id": "canary-v3", "type": "change", "source": "change-control",
            "raw_data": {
                "change_type": "kubernetes_rollout", "version": "v3", "service": "payments",
                "rollout_status": "progressing", "deployed_at": "2026-09-16T10:00:00Z",
            },
        },
        {
            "id": "before", "type": "metric", "source": "prometheus", "name": "http_error_rate", "value": 0.01,
            "raw_data": {"service": "payments", "version": "v2", "window": "before"},
        },
        {
            "id": "canary", "type": "metric", "source": "prometheus", "name": "http_error_rate", "value": 0.30,
            "raw_data": {"service": "payments", "version": "v3", "role": "canary", "window": "after"},
        },
        {
            "id": "stable", "type": "metric", "source": "prometheus", "name": "http_error_rate", "value": 0.01,
            "raw_data": {"service": "payments", "version": "v2", "role": "stable", "window": "after"},
        },
    ]
    incident = AgentInput(
        incident_id="inc-change",
        service_name="payments",
        evidence_summary="canary regression after rollout",
        time_range={"start": "2026-09-16T10:05:00Z", "end": "2026-09-16T10:30:00Z"},
        context={"evidence": evidence, "incident_start": "2026-09-16T10:05:00Z"},
    )
    result = await ChangeAgent(adapter).analyze(incident)
    assert "CHANGE_CORRELATION=" in adapter.prompt
    assert result.analysis_details["candidate_changes"]
    assert result.analysis_details["before_after_deltas"]
    assert "alternative_causes" in result.analysis_details
    assert "rollback_candidate_evidence" in result.analysis_details
    assert result.analysis_details["execution_boundary"] == "analysis_only_no_rollback_execution"
    assert all(action.read_only for action in result.recommended_actions)
    assert all("rollback" not in action.action.lower() for action in result.recommended_actions)
