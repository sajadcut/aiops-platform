import asyncio
from typing import Any, Dict

from agents.shared.base import AgentInput
from agents.shared.coordinator import IncidentCoordinator
from agents.shared.registry import AgentRegistry
from agents.triage import TriageAgent
from integrations.llm.openai_compatible import configured_llm_adapter


class A2AGateway:
    """Compatibility gateway for structured multi-agent analysis.

    This gateway no longer relies on hard-coded localhost endpoints. It uses the
    same registry/routing policy as the main orchestrator and remains analysis-only.
    """

    def __init__(self):
        self.llm = configured_llm_adapter()
        self.triage = TriageAgent(self.llm)
        self.registry = AgentRegistry(self.llm)
        self.coordinator = IncidentCoordinator()

    async def process_incident(self, incident_data: Dict[str, Any]) -> Dict[str, Any]:
        input_data = AgentInput(
            incident_id=incident_data.get("incident_id"),
            evidence_summary=str(incident_data.get("summary") or ""),
            service_name=incident_data.get("service"),
            context=incident_data.get("context") or {},
        )
        triage = await self.triage.analyze(input_data)
        triage_data = triage.model_dump(mode="json")
        routing = self.coordinator.select_agents(triage_data, self.registry.enabled_names())
        agents = [self.registry.get(name) for name in routing["selected"]]
        agents = [agent for agent in agents if agent is not None]
        results = await asyncio.gather(*(agent.analyze(input_data) for agent in agents), return_exceptions=True)
        findings = []
        for agent, result in zip(agents, results):
            if isinstance(result, Exception):
                findings.append({
                    "agent_name": agent.name,
                    "finding_type": f"{agent.name}_error",
                    "confidence": 0.0,
                    "evidence_ids": [],
                    "missing_evidence": ["successful specialist analysis"],
                    "requires_human_review": True,
                })
            else:
                findings.append(result.model_dump(mode="json"))
        coordination = self.coordinator.synthesize(findings)
        return {
            "triage": triage_data,
            "routing": routing,
            "analysis": findings,
            "coordination": coordination,
            "execution_boundary": "analysis_only",
        }
