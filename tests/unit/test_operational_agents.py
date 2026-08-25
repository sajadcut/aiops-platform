import json

import pytest

from agents.application import ApplicationAgent
from agents.infrastructure import InfrastructureAgent
from agents.kubernetes import KubernetesAgent
from agents.security import SecurityAgent
from agents.shared.base import AgentInput
from agents.triage import TriageAgent
from agents.vm import VMAgent
from integrations.llm.base import LLMAdapter, LLMResponse


class StaticLLM(LLMAdapter):
    def __init__(self, payload):
        self.payload = payload

    @property
    def provider_name(self) -> str:
        return "static-test"

    async def generate(self, prompt, system_prompt=None, temperature=0.7, max_tokens=1000, **kwargs):
        return LLMResponse(content=json.dumps(self.payload), model="static-test")

    async def generate_with_messages(self, messages, temperature=0.7, max_tokens=1000, **kwargs):
        return await self.generate(messages[-1]["content"], temperature=temperature, max_tokens=max_tokens)


def incident_input():
    return AgentInput(
        incident_id="incident-1",
        service_name="payments-api",
        evidence_summary="Elevated latency and authentication errors",
        context={
            "summary": {"source": "test"},
            "evidence": [
                {"id": "log-1", "type": "log", "source": "elasticsearch", "message": "401 responses increased"},
                {"id": "metric-1", "type": "metric", "source": "prometheus", "name": "latency", "value": 2.1},
                {"id": "alert-1", "type": "alert", "source": "zabbix", "severity": "high"},
            ],
            "knowledge_results": [{"source_id": "rag-1", "title": "Authentication runbook", "relevance": 0.91}],
            "memory_results": [{"id": "memory-1", "pattern": "past auth latency incident", "outcome": "verified"}],
        },
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "agent_cls,payload",
    [
        (ApplicationAgent, {"severity":"high","health_status":"degraded","error_patterns":["401 spike"],"deployment_correlation":"unconfirmed","dependency_signals":[],"affected_components":["payments-api"],"blast_radius":"single service","hypotheses":[{"hypothesis":"auth dependency degradation","probability":0.7,"evidence_ids":["log-1","metric-1","rag-1"],"conflicting_evidence_ids":["alert-1","memory-1"],"falsification_checks":["compare auth dependency latency"]}],"missing_evidence":[],"handoff_agents":["security"],"immediate_checks":["Inspect correlated application logs"],"confidence":0.8}),
        (InfrastructureAgent, {"severity":"medium","health_status":"degraded","saturation_signals":["latency elevated"],"capacity_risks":[],"network_signals":[],"node_signals":[],"affected_components":["payments-api"],"blast_radius":"single service","hypotheses":[],"missing_evidence":[],"handoff_agents":["application"],"immediate_checks":["Inspect service latency metrics"],"confidence":0.7}),
        (KubernetesAgent, {"severity":"medium","health_status":"degraded","workload_signals":["service latency elevated"],"rollout_signals":[],"scheduling_signals":[],"network_signals":[],"resource_signals":[],"affected_components":["payments-api"],"blast_radius":"single workload","hypotheses":[],"missing_evidence":[],"handoff_agents":["application"],"immediate_checks":["Inspect workload status"],"confidence":0.7}),
        (SecurityAgent, {"severity":"high","health_status":"degraded","authentication_signals":["401 increase"],"authorization_signals":[],"suspicious_signals":["authentication failures"],"exposure_signals":[],"policy_signals":[],"affected_components":["payments-api"],"blast_radius":"single service","hypotheses":[],"missing_evidence":[],"handoff_agents":["application"],"immediate_checks":["Inspect authentication logs"],"containment_recommendations":["Disable compromised credential only if compromise is independently confirmed"],"confidence":0.8}),
        (VMAgent, {"severity":"medium","health_status":"degraded","reachability":"unknown","cpu_signals":[],"memory_signals":[],"disk_signals":[],"network_signals":[],"process_signals":[],"service_signals":[],"log_signals":["authentication errors"],"affected_components":["payments-api"],"blast_radius":"unknown","hypotheses":[],"missing_evidence":[],"handoff_agents":["infrastructure"],"immediate_checks":["Collect VM telemetry"],"remediation_candidates":[],"confidence":0.6}),
    ],
)
async def test_specialized_agents_preserve_evidence_and_operational_contract(agent_cls, payload):
    result = await agent_cls(StaticLLM(payload)).analyze(incident_input())
    assert result.evidence_count == 3
    assert set(result.evidence_ids) == {"log-1", "metric-1", "alert-1"}
    assert "rag-1" not in result.evidence_ids
    assert "memory-1" not in result.evidence_ids
    assert 0 <= result.confidence <= 1
    assert result.severity != "unknown"
    assert result.recommended_actions
    assert all(action.read_only for action in result.recommended_actions if action.purpose == "investigation")
    if result.hypotheses:
        assert "rag-1" not in result.hypotheses[0].evidence_ids
        assert "memory-1" not in result.hypotheses[0].conflicting_evidence_ids


@pytest.mark.asyncio
async def test_security_write_recommendation_is_never_direct_execution():
    payload = {
        "severity":"critical","health_status":"degraded","authentication_signals":["credential misuse suspected"],
        "authorization_signals":[],"suspicious_signals":["suspicious login sequence"],"exposure_signals":[],"policy_signals":[],
        "affected_components":["payments-api"],"blast_radius":"unknown","hypotheses":[],"missing_evidence":[],
        "handoff_agents":[],"immediate_checks":["Inspect authentication logs"],"containment_recommendations":["Revoke the credential"],"confidence":0.9,
    }
    result = await SecurityAgent(StaticLLM(payload)).analyze(incident_input())
    containment = [a for a in result.recommended_actions if not a.read_only]
    assert containment
    assert all(a.requires_approval for a in containment)
    assert result.requires_approval is True


@pytest.mark.asyncio
async def test_triage_routes_specialists_and_exposes_evidence_gaps():
    payload = {
        "primary_domain":"security","secondary_domains":["application"],"severity":"high","health_status":"degraded",
        "urgency_reason":"authentication failures are elevated","affected_components":["payments-api"],"blast_radius":"single service",
        "hypotheses":[],"missing_evidence":["identity-provider audit trail"],"specialist_routes":["security","application"],
        "immediate_checks":["Collect identity-provider audit trail"],"confidence":0.85,
    }
    result = await TriageAgent(StaticLLM(payload)).analyze(incident_input())
    assert result.finding_type == "triage_security"
    assert result.handoff_agents == ["security", "application"]
    assert "identity-provider audit trail" in result.missing_evidence
    assert result.requires_human_review is True
    assert result.analysis_details["knowledge_context_count"] == 1
    assert result.analysis_details["memory_context_count"] == 1


def test_agent_source_does_not_hardcode_mock_provider_or_fake_vm_os():
    from pathlib import Path
    for path in [
        "agents/application/__init__.py",
        "agents/infrastructure/__init__.py",
        "agents/kubernetes/__init__.py",
        "agents/security/__init__.py",
        "agents/triage/__init__.py",
        "agents/vm/__init__.py",
    ]:
        source = Path(path).read_text(encoding="utf-8")
        assert "MockLLMProvider" not in source
    vm_source = Path("agents/vm/__init__.py").read_text(encoding="utf-8")
    assert "Debian 10" not in vm_source
