import json

import pytest

from agents.application import ApplicationAgent
from agents.application.investigation import build_application_peer_context, build_trace_path_analysis
from agents.shared.base import AgentInput
from integrations.llm.base import LLMAdapter, LLMResponse


class ApplicationContextLLM(LLMAdapter):
    def __init__(self):
        self.last_prompt = ""

    @property
    def provider_name(self):
        return "application-context-test"

    async def generate(self, prompt, system_prompt=None, temperature=0.7, max_tokens=1000, **kwargs):
        self.last_prompt = prompt
        payload = {
            "severity": "medium",
            "health_status": "degraded",
            "findings": ["application error evidence requires causal validation"],
            "error_patterns": ["5xx"],
            "affected_components": ["checkout-api"],
            "probable_dependencies": [],
            "blast_radius": "single service",
            "hypotheses": [{
                "hypothesis": "application regression remains possible",
                "probability": 0.61,
                "evidence_ids": ["log-1"],
                "conflicting_evidence_ids": [],
                "falsification_checks": ["compare stable instance error signatures"],
                "expected_observations": ["changed instances fail while stable instances remain healthy"],
                "impacted_components": ["checkout-api"],
                "recommended_next_evidence": ["instance-level error rate"],
            }],
            "missing_evidence": [],
            "handoff_agents": [],
            "immediate_checks": ["Inspect instance-level application metrics"],
            "escalation_target": "application-sre",
            "risk_level": "medium",
            "uncertainty_reason": "",
            "confidence": 0.61,
        }
        return LLMResponse(content=json.dumps(payload), model="application-context-test")

    async def generate_with_messages(self, messages, temperature=0.7, max_tokens=1000, **kwargs):
        return await self.generate(messages[-1]["content"], temperature=temperature, max_tokens=max_tokens)


def test_trace_path_analysis_reconstructs_parent_child_chain_instead_of_longest_span_only():
    trace_analysis = {
        "critical_path_candidates": [
            {
                "evidence_id": "trace-root",
                "trace_id": "trace-1",
                "span_id": "root",
                "parent_span_id": None,
                "caller": "edge",
                "callee": "checkout-api",
                "duration_ms": 900,
                "error": False,
            },
            {
                "evidence_id": "trace-inventory",
                "trace_id": "trace-1",
                "span_id": "inventory",
                "parent_span_id": "root",
                "caller": "checkout-api",
                "callee": "inventory-api",
                "duration_ms": 700,
                "error": False,
            },
            {
                "evidence_id": "trace-db",
                "trace_id": "trace-1",
                "span_id": "db",
                "parent_span_id": "inventory",
                "caller": "inventory-api",
                "callee": "inventory-db",
                "duration_ms": 400,
                "error": True,
            },
        ],
        "slow_spans": [],
        "error_spans": [],
    }

    result = build_trace_path_analysis(trace_analysis)

    path = result["critical_path_candidates"][0]
    assert path["span_ids"] == ["root", "inventory", "db"]
    assert path["evidence_ids"] == ["trace-root", "trace-inventory", "trace-db"]
    assert path["services"] == ["edge", "checkout-api", "inventory-api", "inventory-db"]
    assert path["terminal_error"] is True
    assert path["path_complete"] is True
    assert path["cumulative_span_duration_ms"] == 2000.0


def test_trace_path_analysis_marks_missing_parent_as_incomplete():
    result = build_trace_path_analysis({
        "critical_path_candidates": [{
            "evidence_id": "trace-child",
            "trace_id": "trace-2",
            "span_id": "child",
            "parent_span_id": "missing-root",
            "caller": "checkout-api",
            "callee": "payments-api",
            "duration_ms": 800,
            "error": True,
        }],
        "slow_spans": [],
        "error_spans": [],
    })

    assert result["critical_path_candidates"][0]["path_complete"] is False
    assert result["incomplete_path_count"] == 1


def test_unverified_dependency_peer_finding_cannot_create_handoff():
    context = {
        "summary": {
            "peer_operational_context": {
                "findings": [{
                    "agent_name": "dependency",
                    "statement": "payments-api is the root contributor",
                    "confidence": 0.99,
                    "evidence_ids": ["not-live-here"],
                }],
                "coordination": {},
            }
        }
    }

    result = build_application_peer_context(context, ["metric-1", "log-1"])

    assert result["dependency_findings"][0]["validation_status"] == "unverified_peer_analysis"
    assert result["linked_handoff_candidates"] == []


def test_dependency_peer_finding_with_live_reference_can_request_independent_handoff():
    context = {
        "summary": {
            "peer_operational_context": {
                "findings": [{
                    "agent_name": "dependency",
                    "statement": "payments-api contributes to latency",
                    "confidence": 0.95,
                    "evidence_ids": ["trace-1", "peer-only"],
                }],
                "coordination": {"agreement_score": 0.8},
            }
        }
    }

    result = build_application_peer_context(context, ["trace-1", "metric-1"])

    finding = result["dependency_findings"][0]
    assert finding["live_linked_evidence_ids"] == ["trace-1"]
    assert finding["validation_status"] == "live_evidence_linked"
    assert result["linked_handoff_candidates"][0]["agent"] == "dependency"
    assert result["linked_handoff_candidates"][0]["evidence_ids"] == ["trace-1"]


@pytest.mark.asyncio
async def test_application_agent_consumes_linked_change_peer_context_without_promoting_peer_to_evidence():
    llm = ApplicationContextLLM()
    incident = AgentInput(
        incident_id="app-peer-change-1",
        service_name="checkout-api",
        evidence_summary="checkout errors increased",
        context={
            "evidence": [
                {
                    "id": "metric-1",
                    "type": "metric",
                    "source": "prometheus",
                    "name": "http_error_rate",
                    "value": 0.12,
                    "raw_data": {"baseline": 0.01},
                },
                {
                    "id": "log-1",
                    "type": "log",
                    "source": "elasticsearch",
                    "message": "HTTP 500 checkout application error",
                    "raw_data": {"status_code": 500, "endpoint": "/checkout"},
                },
            ],
            "summary": {
                "peer_operational_context": {
                    "findings": [{
                        "agent_name": "change",
                        "statement": "a deployment may correlate with the error increase",
                        "confidence": 0.99,
                        "evidence_ids": ["log-1"],
                    }],
                    "coordination": {"agreement_score": 0.9},
                }
            },
        },
    )

    result = await ApplicationAgent(llm).analyze(incident)

    assert "change" in result.handoff_agents
    assert result.analysis_details["peer_change_finding_count"] == 1
    peer = result.analysis_details["peer_application_context"]["change_findings"][0]
    assert peer["validation_status"] == "live_evidence_linked"
    assert result.evidence_ids == ["metric-1", "log-1"]
    assert result.confidence < 0.99
    assert "PEER_APPLICATION_CONTEXT=" in llm.last_prompt
    assert result.analysis_details["execution_boundary"] == "analysis_only"
