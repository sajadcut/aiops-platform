import json

import pytest

from agents.application import ApplicationAgent
from agents.application.engine import build_application_analysis
from agents.shared.base import AgentInput
from integrations.llm.base import LLMAdapter, LLMResponse


class StaticApplicationLLM(LLMAdapter):
    def __init__(self, payload=None):
        self.payload = payload or {
            "severity": "high",
            "health_status": "degraded",
            "findings": ["application symptom observed"],
            "error_patterns": ["5xx"],
            "affected_components": ["checkout-api"],
            "probable_dependencies": [],
            "blast_radius": "single service",
            "hypotheses": [{
                "hypothesis": "candidate application regression",
                "probability": 0.7,
                "evidence_ids": ["log-1"],
                "conflicting_evidence_ids": [],
                "falsification_checks": ["Compare stable and changed instances"],
                "expected_observations": ["Only changed instances show the elevated error signature"],
                "impacted_components": ["checkout-api"],
                "recommended_next_evidence": ["instance-level error rate"],
            }],
            "missing_evidence": [],
            "handoff_agents": [],
            "immediate_checks": ["Inspect application logs and metrics"],
            "escalation_target": "application-sre",
            "risk_level": "medium",
            "uncertainty_reason": "",
            "confidence": 0.8,
        }

    @property
    def provider_name(self):
        return "static-application"

    async def generate(self, prompt, system_prompt=None, temperature=0.7, max_tokens=1000, **kwargs):
        return LLMResponse(content=json.dumps(self.payload), model="static-application")

    async def generate_with_messages(self, messages, temperature=0.7, max_tokens=1000, **kwargs):
        return await self.generate(messages[-1]["content"], temperature=temperature, max_tokens=max_tokens)


def analyze(evidence):
    return build_application_analysis(evidence, service_name="checkout-api", context={})


def metric(evidence_id, name, value, baseline, timestamp="2026-09-16T10:05:00Z", **raw):
    return {
        "id": evidence_id,
        "type": "metric",
        "source": "prometheus",
        "name": name,
        "value": value,
        "timestamp": timestamp,
        "raw_data": {"baseline": baseline, **raw},
    }


def test_code_regression_uses_red_baseline_and_nearby_change_without_traffic_spike():
    result = analyze([
        metric("req", "http_request_rate", 102, 100),
        metric("err", "http_error_rate", 0.08, 0.01),
        metric("p95", "http_request_duration_p95", 600, 200),
        metric("p99", "http_request_duration_p99", 950, 250),
        {
            "id": "deploy",
            "type": "change",
            "source": "jenkins",
            "timestamp": "2026-09-16T10:00:00Z",
            "message": "deployment release v42 completed",
            "raw_data": {"release": "v42", "service": "checkout-api"},
        },
        {
            "id": "log-1",
            "type": "log",
            "source": "elasticsearch",
            "timestamp": "2026-09-16T10:05:00Z",
            "message": "HTTP 500 NullPointerException checkout failed",
            "raw_data": {"endpoint": "/checkout", "status_code": 500},
        },
    ])

    assert result["tail_latency_present"] is True
    assert result["latency_percentiles"]["p95"]
    assert result["latency_percentiles"]["p99"]
    assert result["traffic_vs_regression"]["classification"] == "software_or_config_regression_candidate"
    assert result["change_analysis"]["temporally_close_changes"][0]["evidence_id"] == "deploy"
    assert result["http"]["status_families"]["5xx"] == 1
    assert result["http"]["endpoint_impacts"][0]["endpoint"] == "/checkout"


def test_http_500_with_database_timeout_prefers_database_handoff_candidate():
    result = analyze([
        metric("err", "http_error_rate", 0.3, 0.01),
        {
            "id": "log-1",
            "type": "log",
            "source": "elasticsearch",
            "message": "HTTP 500 database timeout PostgreSQL connection pool exhausted",
            "raw_data": {"endpoint": "/checkout", "status_code": 500, "downstream": "postgres-primary"},
        },
    ])

    handoffs = {row["agent"] for row in result["dependency_analysis"]["handoff_candidates"]}
    assert "database" in handoffs
    assert "dependency" in handoffs


def test_downstream_api_latency_is_visible_in_trace_critical_path_and_dependency_handoff():
    result = analyze([
        metric("p95", "http_request_duration_p95", 1200, 250),
        {
            "id": "trace-1",
            "type": "trace",
            "source": "elastic",
            "message": "slow downstream span",
            "raw_data": {
                "trace_id": "t1",
                "span_id": "s1",
                "caller": "checkout-api",
                "callee": "inventory-api",
                "duration_ms": 1100,
                "status": "ok",
            },
        },
        {
            "id": "trace-2",
            "type": "trace",
            "source": "elastic",
            "message": "inventory timeout",
            "raw_data": {
                "trace_id": "t1",
                "span_id": "s2",
                "parent_span_id": "s1",
                "caller": "checkout-api",
                "callee": "inventory-api",
                "duration_ms": 1300,
                "status": "error",
                "error": True,
            },
        },
    ])

    trace = result["trace_analysis"]
    assert trace["trace_evidence_count"] == 2
    assert trace["critical_path_candidates"][0]["evidence_id"] == "trace-2"
    assert trace["downstream_contributors"][0]["service"] == "inventory-api"
    assert any(row["agent"] == "dependency" for row in result["dependency_analysis"]["handoff_candidates"])


def test_traffic_spike_without_saturation_or_error_growth_is_not_regression():
    result = analyze([
        metric("req", "http_request_rate", 220, 100),
        metric("err", "http_error_rate", 0.01, 0.01),
        metric("p95", "http_request_duration_p95", 210, 200),
        {"id": "log-1", "type": "log", "source": "elasticsearch", "message": "requests healthy normal success"},
    ])

    assert result["traffic_vs_regression"]["classification"] == "traffic_spike_without_regression_evidence"


def test_memory_leak_pressure_is_extracted_from_metrics_and_logs():
    result = analyze([
        metric("heap", "app_heap_memory_bytes", 900, 400),
        metric("gc", "gc_pause_ms", 350, 40),
        {"id": "log-1", "type": "log", "source": "elasticsearch", "message": "heap memory pressure with long GC pause"},
    ])

    assert result["resource_pressure"]["memory_gc"]
    assert "log-1" in result["resource_keyword_signals"]["memory_gc"]
    assert any(row["kind"] == "memory_gc" for row in result["baseline_deltas"])


def test_thread_pool_exhaustion_and_backpressure_are_explicit():
    result = analyze([
        metric("workers", "thread_pool_active_workers", 100, 40),
        {"id": "log-1", "type": "log", "source": "elasticsearch", "message": "thread pool exhausted all workers busy queue full backpressure"},
    ])

    assert result["resource_pressure"]["thread_pool"]
    assert "log-1" in result["resource_keyword_signals"]["thread_pool"]
    assert "log-1" in result["resource_keyword_signals"]["queue_backpressure"]


def test_nearby_deploy_without_error_or_latency_delta_is_only_correlation():
    result = analyze([
        metric("req", "http_request_rate", 100, 100),
        metric("err", "http_error_rate", 0.01, 0.01),
        metric("p95", "http_request_duration_p95", 200, 200),
        {
            "id": "deploy",
            "type": "change",
            "source": "jenkins",
            "timestamp": "2026-09-16T10:00:00Z",
            "message": "deployment release v42 completed",
        },
        {
            "id": "log-1",
            "type": "log",
            "source": "elasticsearch",
            "timestamp": "2026-09-16T10:05:00Z",
            "message": "request success healthy normal",
        },
    ])

    assert result["change_analysis"]["candidate_changes"]
    assert result["traffic_vs_regression"]["classification"] != "software_or_config_regression_candidate"
    assert "correlation only" in result["change_analysis"]["policy"]


def test_conflicting_metrics_and_logs_are_exposed_instead_of_hidden():
    result = analyze([
        {
            "id": "metric-healthy",
            "type": "metric",
            "source": "prometheus",
            "name": "application_availability",
            "value": 1,
            "raw_data": {"message": "service healthy normal available"},
        },
        {
            "id": "log-fail",
            "type": "log",
            "source": "elasticsearch",
            "message": "HTTP 500 timeout checkout failed",
        },
    ])

    assert result["conflicts"]
    conflict = result["conflicts"][0]
    assert "metric-healthy" in conflict["conflicting_healthy_evidence_ids"]
    assert "log-fail" in conflict["supporting_failure_evidence_ids"]


@pytest.mark.asyncio
async def test_agent_preserves_expected_observation_and_auto_handoffs_on_stronger_downstream_evidence():
    incident = AgentInput(
        incident_id="app-db-1",
        service_name="checkout-api",
        evidence_summary="HTTP 500 while database pool is exhausted",
        context={"evidence": [
            metric("err", "http_error_rate", 0.25, 0.01),
            {
                "id": "log-1",
                "type": "log",
                "source": "elasticsearch",
                "message": "HTTP 500 database timeout PostgreSQL connection pool exhausted",
                "raw_data": {"endpoint": "/checkout", "status_code": 500, "downstream": "postgres-primary"},
            },
        ]},
    )

    result = await ApplicationAgent(StaticApplicationLLM()).analyze(incident)

    assert "database" in result.handoff_agents
    assert result.analysis_details["dependency_analysis"]["handoff_candidates"]
    assert result.analysis_details["hypothesis_expected_observations"][0]["expected_observations"] == [
        "Only changed instances show the elevated error signature"
    ]
    assert any("Expected if true:" in check for check in result.hypotheses[0].falsification_checks)
    assert result.analysis_details["execution_boundary"] == "analysis_only"


@pytest.mark.asyncio
async def test_mutating_application_recommendation_remains_approval_required():
    payload = StaticApplicationLLM().payload.copy()
    payload["immediate_checks"] = ["rollback deployment and restart checkout service"]
    incident = AgentInput(
        incident_id="write-boundary",
        service_name="checkout-api",
        evidence_summary="regression",
        context={"evidence": [
            metric("err", "http_error_rate", 0.2, 0.01),
            {"id": "log-1", "type": "log", "source": "elasticsearch", "message": "HTTP 500 application error"},
        ]},
    )

    result = await ApplicationAgent(StaticApplicationLLM(payload)).analyze(incident)

    action = result.recommended_actions[0]
    assert action.read_only is False
    assert action.requires_approval is True
    assert result.analysis_details["execution_boundary"] == "analysis_only"
