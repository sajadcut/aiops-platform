import json

import pytest

from agents.infrastructure import InfrastructureAgent
from agents.kubernetes import KubernetesAgent
from agents.shared.base import AgentInput
from agents.shared.coordinator import IncidentCoordinator
from domain.contracts.config import settings
from integrations.llm.base import LLMAdapter, LLMResponse


class KubernetesOOMScenarioLLM(LLMAdapter):
    """Deterministic scenario adapter that still exercises normal Agent parsing/safety."""

    @property
    def provider_name(self):
        return "kubernetes-oom-acceptance"

    async def generate(self, prompt, system_prompt=None, temperature=0.7, max_tokens=1000, **kwargs):
        if "You are a Kubernetes SRE" in prompt:
            payload = {
                "severity": "high",
                "health_status": "degraded",
                "findings": ["payments container was OOMKilled and is restarting"],
                "workload_signals": ["OOMKilled", "BackOff restarting failed container"],
                "resource_signals": ["container memory pressure near limit"],
                "affected_components": ["payments-pod"],
                "blast_radius": "payments workload",
                "hypotheses": [{
                    "hypothesis": "workload memory pressure exceeds container limit",
                    "probability": 0.92,
                    "evidence_ids": ["klog-oom", "kmem-high", "kevent-backoff"],
                    "conflicting_evidence_ids": [],
                    "falsification_checks": ["compare memory working set with configured container limit"],
                    "impacted_components": ["payments-pod"],
                    "recommended_next_evidence": ["container memory limit and working set"],
                }],
                "missing_evidence": [],
                "handoff_agents": ["infrastructure"],
                "immediate_checks": ["Inspect pod events, container termination history, memory limit and working set"],
                "escalation_target": "platform-sre",
                "risk_level": "high",
                "uncertainty_reason": "",
                "confidence": 0.92,
            }
        elif "senior infrastructure/SRE analyst" in prompt:
            payload = {
                "severity": "high",
                "health_status": "degraded",
                "findings": ["workload memory pressure is high while node-wide failure is not evidenced"],
                "saturation_signals": ["payments workload memory pressure"],
                "capacity_risks": ["container memory limit pressure"],
                "affected_components": ["payments-pod"],
                "blast_radius": "payments workload",
                "hypotheses": [{
                    "hypothesis": "workload memory pressure exceeds container limit",
                    "probability": 0.84,
                    "evidence_ids": ["kmem-high", "kevent-backoff"],
                    "conflicting_evidence_ids": [],
                    "falsification_checks": ["compare node memory pressure with pod/container usage"],
                    "impacted_components": ["payments-pod"],
                    "recommended_next_evidence": ["node memory pressure and container limit"],
                }],
                "missing_evidence": [],
                "handoff_agents": ["kubernetes"],
                "immediate_checks": ["Inspect workload and node memory metrics"],
                "escalation_target": "infrastructure-sre",
                "risk_level": "high",
                "uncertainty_reason": "",
                "confidence": 0.84,
            }
        else:
            raise AssertionError(f"unexpected scenario prompt: {prompt[:120]}")
        return LLMResponse(content=json.dumps(payload), model="scenario")

    async def generate_with_messages(self, messages, temperature=0.7, max_tokens=1000, **kwargs):
        return await self.generate(messages[-1]["content"], temperature=temperature, max_tokens=max_tokens)


class UnsafeKubernetesRecommendationLLM(LLMAdapter):
    @property
    def provider_name(self):
        return "unsafe-kubernetes-recommendation"

    async def generate(self, prompt, system_prompt=None, temperature=0.7, max_tokens=1000, **kwargs):
        payload = {
            "severity": "high",
            "health_status": "degraded",
            "findings": ["OOMKilled termination observed"],
            "workload_signals": ["OOMKilled"],
            "resource_signals": ["memory pressure"],
            "affected_components": ["payments-pod"],
            "hypotheses": [{
                "hypothesis": "workload memory pressure exceeds container limit",
                "probability": 0.9,
                "evidence_ids": ["klog-oom", "kmem-high", "kevent-backoff"],
                "conflicting_evidence_ids": [],
                "falsification_checks": ["inspect configured memory limit"],
            }],
            "missing_evidence": [],
            "handoff_agents": ["infrastructure"],
            # Deliberately violates the prompt. The common contract must not treat this as read-only.
            "immediate_checks": ["Restart the payments pod"],
            "confidence": 0.9,
        }
        return LLMResponse(content=json.dumps(payload), model="scenario")

    async def generate_with_messages(self, messages, temperature=0.7, max_tokens=1000, **kwargs):
        return await self.generate(messages[-1]["content"], temperature=temperature, max_tokens=max_tokens)


def oom_input():
    return AgentInput(
        incident_id="inc-k8s-oom-001",
        service_name="payments",
        evidence_summary="payments pod is OOMKilled and entering restart backoff",
        context={
            "evidence": [
                {
                    "id": "klog-oom",
                    "type": "log",
                    "source": "kubernetes",
                    "message": "container terminated reason=OOMKilled",
                },
                {
                    "id": "kmem-high",
                    "type": "metric",
                    "source": "prometheus",
                    "name": "container_memory_working_set_ratio",
                    "value": 0.98,
                },
                {
                    "id": "kevent-backoff",
                    "type": "event",
                    "source": "kubernetes",
                    "message": "BackOff restarting failed container payments",
                },
            ]
        },
    )


def test_oom_triage_routes_to_kubernetes_and_infrastructure(monkeypatch):
    monkeypatch.setattr(settings, "AGENT_MAX_PARALLELISM", 6)
    monkeypatch.setattr(settings, "AGENT_LOW_CONFIDENCE_THRESHOLD", 0.5)

    routing = IncidentCoordinator.select_agents(
        {
            "handoff_agents": ["kubernetes", "infrastructure"],
            "analysis_details": {"primary_domain": "kubernetes"},
            "confidence": 0.95,
        },
        enabled=["kubernetes", "infrastructure", "network", "storage", "change", "dependency"],
    )

    assert routing["reason"] == "triage_specialist_routing"
    assert routing["primary_domain"] == "kubernetes"
    assert routing["selected"][:2] == ["kubernetes", "infrastructure"]


@pytest.mark.asyncio
async def test_oom_multi_agent_analysis_is_grounded_and_reaches_consensus():
    adapter = KubernetesOOMScenarioLLM()
    incident = oom_input()

    kubernetes = await KubernetesAgent(adapter).analyze(incident)
    infrastructure = await InfrastructureAgent(adapter).analyze(incident)

    live_ids = {"klog-oom", "kmem-high", "kevent-backoff"}
    for result in (kubernetes, infrastructure):
        assert result.findings
        assert result.confidence > 0
        assert result.evidence_count == 3
        assert set(result.evidence_ids) == live_ids
        assert not result.missing_evidence
        assert not result.requires_human_review
        for hypothesis in result.hypotheses:
            assert set(hypothesis.evidence_ids).issubset(live_ids)
            assert hypothesis.falsification_checks
        assert all(action.read_only for action in result.recommended_actions)
        assert all(not action.requires_approval for action in result.recommended_actions)

    synthesis = IncidentCoordinator.synthesize([
        kubernetes.model_dump(mode="json"),
        infrastructure.model_dump(mode="json"),
    ])

    assert synthesis["disagreement"] is False
    assert synthesis["contradictions"] == []
    assert synthesis["requires_human_review"] is False
    assert synthesis["evidence_count"] == 3
    assert "workload memory pressure exceeds container limit" in synthesis["consensus_hypotheses"]
    assert synthesis["consensus_support"]["workload memory pressure exceeds container limit"] == [
        "infrastructure",
        "kubernetes",
    ]


@pytest.mark.asyncio
async def test_oom_agent_cannot_disguise_restart_as_read_only_investigation():
    result = await KubernetesAgent(UnsafeKubernetesRecommendationLLM()).analyze(oom_input())

    assert len(result.recommended_actions) == 1
    recommendation = result.recommended_actions[0]
    assert recommendation.action == "Restart the payments pod"
    assert recommendation.read_only is False
    assert recommendation.requires_approval is True
    assert recommendation.risk_level == "high"
    assert recommendation.purpose == "untrusted_write_recommendation"
    assert recommendation.suggested_tool is None
