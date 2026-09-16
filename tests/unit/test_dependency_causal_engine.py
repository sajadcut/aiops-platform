import json

import pytest

from agents.dependency import DependencyAgent
from agents.dependency.engine import build_dependency_causal_analysis
from agents.shared.base import AgentInput
from integrations.llm.base import LLMAdapter, LLMResponse


def trace(eid, ts, caller=None, callee=None, **raw):
    payload = {"timestamp": ts, **raw}
    if caller is not None:
        payload["caller"] = caller
    if callee is not None:
        payload["callee"] = callee
    return {
        "id": eid,
        "type": "trace",
        "source": "elasticsearch",
        "raw_data": payload,
    }


def metric(eid, ts, name, value, caller, callee, **raw):
    return {
        "id": eid,
        "type": "metric",
        "source": "prometheus",
        "name": name,
        "value": value,
        "raw_data": {"timestamp": ts, "caller": caller, "callee": callee, **raw},
    }


def service_log(eid, ts, service, message, **raw):
    return {
        "id": eid,
        "type": "log",
        "source": "elasticsearch",
        "message": message,
        "raw_data": {"timestamp": ts, "service": service, **raw},
    }


def analyze(evidence, service="frontend"):
    return build_dependency_causal_analysis(evidence, service_name=service, context={})


def test_database_cascade_selects_deeper_first_failing_edge_not_noisy_upstream():
    result = analyze([
        trace("api-db", "2026-09-16T10:00:00Z", "api", "postgres-primary", error=True, timeout=True, duration_ms=950),
        trace("front-api", "2026-09-16T10:02:00Z", "frontend", "api", error=True, timeout=True, duration_ms=1200),
        service_log("api-errors-1", "2026-09-16T10:02:10Z", "api", "request failed because downstream timed out"),
        service_log("api-errors-2", "2026-09-16T10:02:20Z", "api", "request failed because downstream timed out"),
        service_log("api-errors-3", "2026-09-16T10:02:30Z", "api", "request failed because downstream timed out"),
    ])
    assert result["first_failing_edge"]["edge_id"] == "api->postgres-primary"
    assert result["root_contributors"][0]["edge_id"] == "api->postgres-primary"
    upstream = next(row for row in result["root_contributors"] if row["edge_id"] == "frontend->api")
    assert "deeper_downstream_edge_failed_earlier" in upstream["conflicting_evidence"]
    assert result["cascading_failures"][0]["root_edge"] == "api->postgres-primary"
    assert any(row["agent"] == "database" for row in result["suggested_handoffs"])


def test_external_api_outage_is_classified_and_circuit_breaker_preserved():
    result = analyze([
        trace(
            "checkout-stripe",
            "2026-09-16T11:00:00Z",
            "checkout",
            "api.stripe.com",
            error=True,
            status_code=503,
            circuit_breaker_open=True,
            dependency_type="external_saas",
        ),
    ], service="checkout")
    edge = result["edge_health"][0]
    assert edge["dependency_type"] == "external_api"
    assert edge["circuit_breaker"] == "open"
    assert result["dependency_inventory"]["external_api"][0]["callee"] == "api.stripe.com"
    assert result["circuit_breakers"][0]["edge_id"] == "checkout->api.stripe.com"
    assert any(row["agent"] == "network" for row in result["suggested_handoffs"])


def test_shared_identity_dependency_detects_multi_caller_effect():
    result = analyze([
        trace("svc-a-id", "2026-09-16T12:00:00Z", "orders", "identity-service", error=True, status_code=503),
        trace("svc-b-id", "2026-09-16T12:01:00Z", "payments", "identity-service", error=True, status_code=503),
    ], service="orders")
    shared = result["shared_dependencies"][0]
    assert shared["dependency"] == "identity-service"
    assert shared["affected_callers"] == ["orders", "payments"]
    assert shared["clustered_in_time"] is True
    assert result["root_contributors"][0]["shared_node_effect"]["present"] is True
    assert any(row["agent"] == "identity" for row in result["suggested_handoffs"])


def test_retry_storm_and_timeout_propagation_are_directional():
    result = analyze([
        trace("api-db-timeout", "2026-09-16T13:00:00Z", "api", "postgres-primary", error=True, timeout=True),
        trace("front-api-timeout", "2026-09-16T13:01:00Z", "frontend", "api", error=True, timeout=True),
        metric("front-api-rps", "2026-09-16T13:01:00Z", "request_rate", 100, "frontend", "api"),
        metric("front-api-retries", "2026-09-16T13:01:10Z", "retry_rate", 30, "frontend", "api", baseline=2),
    ])
    retry = result["retry_amplification"][0]
    assert retry["edge_id"] == "frontend->api"
    assert retry["retry_to_request_ratio"] == pytest.approx(0.3)
    propagation = result["timeout_propagation"][0]
    assert propagation["downstream_edge"] == "api->postgres-primary"
    assert propagation["upstream_edge"] == "frontend->api"
    assert propagation["direction"] == "downstream_to_upstream"
    root = next(row for row in result["root_contributors"] if row["edge_id"] == "api->postgres-primary")
    assert root["upstream_retry_amplification"] is True


def test_incomplete_trace_keeps_virtual_unknown_nodes_and_raises_uncertainty():
    result = analyze([
        {
            "id": "child-span",
            "type": "trace",
            "source": "elasticsearch",
            "raw_data": {
                "timestamp": "2026-09-16T14:00:00Z",
                "trace_id": "trace-1",
                "span_id": "child",
                "parent_span_id": "missing-parent",
                "service": "payments",
                "error": True,
            },
        }
    ], service="payments")
    assert result["dependency_graph"]["unknown_virtual_nodes"]
    assert any(node["name"].startswith("unknown::") for node in result["dependency_graph"]["nodes"])
    assert result["trace_completeness"]["missing_parent_reference_count"] == 1
    assert result["uncertainty_level"] == "high"
    assert result["confidence_ceiling"] == pytest.approx(0.55)
    assert "not_proof_of_no_dependency" in result["dependency_graph"]["graph_absence_policy"]


def test_unrelated_downstream_error_volume_does_not_override_edge_causality():
    evidence = [
        trace("pay-id", "2026-09-16T15:00:00Z", "payments", "identity-service", error=True, status_code=503),
        trace("pay-reporting", "2026-09-16T15:00:30Z", "payments", "reporting", status="ok"),
    ]
    evidence.extend(
        service_log(f"reporting-{index}", f"2026-09-16T15:01:{index:02d}Z", "reporting", "unrelated batch parse error")
        for index in range(10)
    )
    result = analyze(evidence, service="payments")
    assert result["root_contributors"][0]["edge_id"] == "payments->identity-service"
    assert all(row["edge_id"] != "payments->reporting" for row in result["root_contributors"])
    reporting = next(node for node in result["dependency_graph"]["nodes"] if node["name"] == "reporting")
    assert reporting["health_status"] == "degraded"


class CapturingDependencyLLM(LLMAdapter):
    def __init__(self):
        self.prompt = ""

    @property
    def provider_name(self):
        return "dependency-capturing-test"

    async def generate(self, prompt, system_prompt=None, temperature=0.7, max_tokens=1000, **kwargs):
        self.prompt = prompt
        payload = {
            "severity": "high",
            "health_status": "degraded",
            "findings": ["database edge failed before upstream caller edge"],
            "affected_components": ["frontend", "api"],
            "probable_dependencies": ["postgres-primary"],
            "blast_radius": "frontend path",
            "hypotheses": [{
                "hypothesis": "database dependency is a causal contributor candidate",
                "probability": 0.99,
                "evidence_ids": ["api-db", "front-api"],
                "conflicting_evidence_ids": [],
                "falsification_checks": ["verify direct database health"],
                "impacted_components": ["api"],
                "recommended_next_evidence": ["complete trace parent chain"],
            }],
            "missing_evidence": [],
            "handoff_agents": ["application"],
            "immediate_checks": ["inspect direct database health and per-edge latency"],
            "confidence": 0.99,
        }
        return LLMResponse(content=json.dumps(payload), model="scenario")

    async def generate_with_messages(self, messages, temperature=0.7, max_tokens=1000, **kwargs):
        return await self.generate(messages[-1]["content"], temperature=temperature, max_tokens=max_tokens)


@pytest.mark.asyncio
async def test_dependency_agent_exposes_graph_and_caps_confidence_for_incomplete_traces():
    adapter = CapturingDependencyLLM()
    evidence = [
        trace("api-db", "2026-09-16T16:00:00Z", "api", "postgres-primary", error=True, timeout=True),
        trace("front-api", "2026-09-16T16:02:00Z", "frontend", "api", error=True, timeout=True),
    ]
    incident = AgentInput(
        incident_id="inc-dependency",
        service_name="frontend",
        evidence_summary="database timeout propagated upstream",
        context={"evidence": evidence},
    )
    result = await DependencyAgent(adapter).analyze(incident)
    assert "DEPENDENCY_CAUSAL_ANALYSIS=" in adapter.prompt
    assert result.analysis_details["dependency_graph"]["directed"] is True
    assert result.analysis_details["root_contributors"]
    assert result.analysis_details["first_failing_edge"]["edge_id"] == "api->postgres-primary"
    assert result.analysis_details["execution_boundary"] == "analysis_only"
    ceiling = result.analysis_details["confidence_ceiling"]
    assert result.confidence <= ceiling
    assert all(hypothesis.probability <= ceiling for hypothesis in result.hypotheses)
    assert all(action.read_only for action in result.recommended_actions)
