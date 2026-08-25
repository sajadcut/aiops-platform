import json

import pytest

from agents.dependency import DependencyAgent
from agents.shared.base import AgentInput
from agents.shared.coordinator import IncidentCoordinator
from domain.contracts.config import settings
from integrations.llm.base import LLMAdapter, LLMResponse


class StaticLLM(LLMAdapter):
    def __init__(self, payload): self.payload = payload
    @property
    def provider_name(self): return "static"
    async def generate(self, prompt, system_prompt=None, temperature=0.7, max_tokens=1000, **kwargs):
        return LLMResponse(content=json.dumps(self.payload), model="static")
    async def generate_with_messages(self, messages, temperature=0.7, max_tokens=1000, **kwargs):
        return await self.generate(messages[-1]["content"])


PAYLOAD = {
    "severity":"medium","health_status":"degraded","findings":["dependency latency signal"],
    "affected_components":["payments"],"probable_dependencies":["identity"],"blast_radius":"single service",
    "hypotheses":[{"hypothesis":"dependency degradation","probability":0.8,"evidence_ids":["e1"],"conflicting_evidence_ids":[],"falsification_checks":["compare direct dependency latency"]}],
    "missing_evidence":[],"handoff_agents":["application"],"immediate_checks":["inspect dependency metrics"],
    "auxiliary_conflicts":["memory suggests restart but live evidence shows dependency latency"],"confidence":0.8,
}


def agent_input(source):
    return AgentInput(
        incident_id="source-quality",
        service_name="payments",
        evidence_summary="dependency latency",
        context={
            "evidence":[
                {"id":"e1","type":"metric","source":source,"name":"latency","value":2.0},
                {"id":"e2","type":"log","source":source,"message":"dependency timeout"},
            ],
            "memory_results":[{"id":"mem-1","outcome":"restart once helped"}],
        },
    )


@pytest.mark.asyncio
async def test_unknown_source_cannot_receive_trusted_source_confidence(monkeypatch):
    monkeypatch.setattr(settings, "AGENT_SOURCE_QUALITY_WEIGHTS", {"prometheus":0.95,"unknown":0.4})
    trusted = await DependencyAgent(StaticLLM(PAYLOAD)).analyze(agent_input("prometheus"))
    unknown = await DependencyAgent(StaticLLM(PAYLOAD)).analyze(agent_input("unregistered-source"))
    assert trusted.evidence_quality == 0.95
    assert unknown.evidence_quality == 0.4
    assert trusted.confidence > unknown.confidence


@pytest.mark.asyncio
async def test_auxiliary_conflict_is_recorded_but_not_promoted_to_live_evidence(monkeypatch):
    monkeypatch.setattr(settings, "AGENT_SOURCE_QUALITY_WEIGHTS", {"prometheus":0.95,"unknown":0.4})
    result = await DependencyAgent(StaticLLM(PAYLOAD)).analyze(agent_input("prometheus"))
    assert result.auxiliary_conflicts
    assert "mem-1" not in result.evidence_ids
    coordination = IncidentCoordinator.synthesize([result.model_dump(mode="json")])
    assert coordination["auxiliary_conflicts"][0]["agent"] == "dependency"
    assert coordination["contradictions"] == []
