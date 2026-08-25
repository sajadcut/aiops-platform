import json

import pytest

from agents.dependency import DependencyAgent
from agents.messaging import MessagingAgent
from agents.recovery import RecoveryAgent
from agents.shared.a2a_agent import A2AAgent, A2AAgentCard
from agents.shared.base import AgentOutput, OperationalHypothesis, RecommendedAction
from agents.shared.coordinator import IncidentCoordinator
from agents.shared.registry import AgentRegistry
from agents.shared.telemetry import AgentTelemetry
from apps.context_service.evidence_collector import EvidenceCollector
from apps.evaluator.gate import EvaluationGate
from domain.contracts.config import settings
from integrations.llm.base import LLMAdapter, LLMResponse


class StaticLLM(LLMAdapter):
    def __init__(self, payload=None):
        self.payload = payload or {}

    @property
    def provider_name(self):
        return "static"

    async def generate(self, prompt, system_prompt=None, temperature=0.7, max_tokens=1000, **kwargs):
        return LLMResponse(content=json.dumps(self.payload), model="static")

    async def generate_with_messages(self, messages, temperature=0.7, max_tokens=1000, **kwargs):
        return await self.generate(messages[-1]["content"])


class DummyA2A(A2AAgent):
    async def handle_request(self, request):
        return request


class FakeZabbix:
    def __init__(self): self.calls = 0
    async def get_alerts(self, **kwargs): self.calls += 1; return []


class FakeElastic:
    def __init__(self): self.calls = 0
    async def get_logs(self, *args, **kwargs): self.calls += 1; return []


class FakeProm:
    def __init__(self): self.calls = 0
    async def get_metrics(self, *args, **kwargs): self.calls += 1; return []


@pytest.mark.parametrize("agent_cls", [DependencyAgent, MessagingAgent, RecoveryAgent])
def test_new_operational_specialists_have_analysis_only_contract(agent_cls):
    agent = agent_cls(StaticLLM())
    assert agent.name in {"dependency", "messaging", "recovery"}
    assert agent.allowed_tools
    assert all("execute" not in tool and "write" not in tool for tool in agent.allowed_tools)


def test_registry_manifest_reports_enabled_and_disabled(monkeypatch):
    monkeypatch.setattr(settings, "AGENT_ENABLED_AGENTS", ["dependency", "application"])
    registry = AgentRegistry(StaticLLM())
    manifests = {item.name: item for item in registry.manifests(include_disabled=True)}
    assert manifests["dependency"].enabled is True
    assert manifests["messaging"].enabled is False
    assert manifests["recovery"].enabled is False
    assert manifests["dependency"].production_status == "analysis_only"


def test_agent_output_derives_evidence_conflicts_checks_and_requests(monkeypatch):
    monkeypatch.setattr(settings, "AGENT_MAX_DYNAMIC_EVIDENCE_TYPES", 5)
    output = AgentOutput(
        agent_name="database",
        finding_type="database_analysis",
        statement="connection pressure",
        confidence=0.6,
        evidence_ids=["m1", "l1"],
        evidence_count=2,
        evidence_coverage=0.5,
        hypotheses=[OperationalHypothesis(
            hypothesis="connection exhaustion",
            probability=0.6,
            evidence_ids=["m1"],
            conflicting_evidence_ids=["l1"],
        )],
        missing_evidence=["fresh database metric evidence", "authentication audit log"],
        recommended_actions=[RecommendedAction(action="inspect pool metrics", read_only=True)],
    )
    assert output.supporting_evidence_ids == ["m1"]
    assert output.conflicting_evidence_ids == ["l1"]
    assert output.recommended_checks == ["inspect pool metrics"]
    assert {r.evidence_type for r in output.evidence_requests} == {"metric", "log"}


def test_coordinator_detects_cross_agent_evidence_contradiction(monkeypatch):
    monkeypatch.setattr(settings, "AGENT_CONFLICT_CONFIDENCE_PENALTY", 0.2)
    monkeypatch.setattr(settings, "AGENT_DISAGREEMENT_CONFIDENCE_FACTOR", 0.75)
    monkeypatch.setattr(settings, "AGENT_MISSING_EVIDENCE_CONFIDENCE_FACTOR", 0.85)
    findings = [
        {"agent_name":"application","severity":"high","health_status":"degraded","confidence":0.8,"evidence_coverage":1.0,"evidence_ids":["e1"],"hypotheses":[{"hypothesis":"dependency fault","evidence_ids":["e1"],"conflicting_evidence_ids":[]}],"missing_evidence":[],"handoff_agents":[],"evidence_requests":[]},
        {"agent_name":"dependency","severity":"high","health_status":"degraded","confidence":0.8,"evidence_coverage":1.0,"evidence_ids":["e1"],"hypotheses":[{"hypothesis":"dependency healthy","evidence_ids":[],"conflicting_evidence_ids":["e1"]}],"missing_evidence":[],"handoff_agents":[],"evidence_requests":[]},
    ]
    result = IncidentCoordinator.synthesize(findings)
    assert result["disagreement"] is True
    assert result["contradictions"]
    assert result["requires_human_review"] is True
    assert result["agreement_score"] < 1.0


@pytest.mark.asyncio
async def test_targeted_evidence_collection_does_not_run_unrequested_connectors(monkeypatch):
    monkeypatch.setattr(settings, "AGENT_MAX_DYNAMIC_EVIDENCE_TYPES", 5)
    z, e, p = FakeZabbix(), FakeElastic(), FakeProm()
    collector = EvidenceCollector(zabbix=z, elasticsearch=e, prometheus=p)
    from datetime import datetime, timezone
    result = await collector.collect_requested(
        "payments",
        datetime.now(timezone.utc),
        [{"evidence_type":"log"}, {"evidence_type":"run-this-command"}],
    )
    assert e.calls == 1
    assert z.calls == 0
    assert p.calls == 0
    assert result["requested_types"] == ["log"]


@pytest.mark.asyncio
async def test_a2a_rejects_untrusted_target_before_sending(monkeypatch):
    monkeypatch.setattr(settings, "A2A_ALLOWED_TARGETS", ["https://agent.internal"])
    monkeypatch.setattr(settings, "A2A_REQUIRE_HTTPS", True)
    agent = DummyA2A(A2AAgentCard(name="test", description="test", version="1", endpoint="/a2a"))
    with pytest.raises(ValueError, match="a2a_target_not_allowlisted"):
        await agent.send_request("https://evil.example/rpc", {})
    with pytest.raises(ValueError, match="a2a_https_required"):
        await agent.send_request("http://agent.internal/rpc", {})
    await agent.close()


def test_telemetry_result_record_is_idempotent(monkeypatch):
    monkeypatch.setattr(settings, "AGENT_LOW_CONFIDENCE_THRESHOLD", 0.55)
    AgentTelemetry.clear()
    AgentTelemetry.record("application", success=True)
    AgentTelemetry.record_result("application", confidence=0.8, evidence_coverage=0.75)
    AgentTelemetry.record_result("application", confidence=0.1, evidence_coverage=0.1, disagreement=True, conflict_count=2)
    row = AgentTelemetry.snapshot()["application"]
    assert row["invocations"] == 1
    assert row["result_records"] == 1
    assert row["avg_confidence"] == 0.8
    assert row["avg_evidence_coverage"] == 0.75
    assert row["disagreements"] == 1
    assert row["collaboration_contradictions"] == 2


def test_evaluator_blocks_conflicts_consensus_failure_and_specialist_failure(monkeypatch):
    monkeypatch.setattr(settings, "AGENT_MIN_CONSENSUS_SCORE", 0.6)
    findings = [{
        "agent_name":"database","finding_type":"database_error","confidence":0.9,"evidence_ids":["e1"],
        "evidence_coverage":1.0,"missing_evidence":["successful specialist analysis"],"requires_human_review":True,
        "hypotheses":[],"recommended_actions":[],
    }]
    result = EvaluationGate.evaluate(findings, "manual review", coordination={
        "disagreement":True,"contradictions":[{"evidence_id":"e1"}],"agreement_score":0.2,"requires_human_review":True,
    })
    assert result["approved_for_decision"] is False
    for blocker in ["specialist_failure", "unresolved_evidence_conflict", "human_review_required"]:
        assert blocker in result["blockers"]
