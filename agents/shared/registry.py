from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional, Type

from agents.application import ApplicationAgent
from agents.change import ChangeAgent
from agents.database import DatabaseAgent
from agents.identity import IdentityAgent
from agents.infrastructure import InfrastructureAgent
from agents.kubernetes import KubernetesAgent
from agents.network import NetworkAgent
from agents.security import SecurityAgent
from agents.shared.base import BaseAgent
from agents.shared.domain_agent import DomainDiagnosticAgent
from agents.storage import StorageAgent
from agents.vm import VMAgent
from domain.contracts.config import settings
from integrations.llm.base import LLMAdapter


@dataclass(frozen=True)
class AgentManifest:
    name: str
    domain: str
    version: str
    description: str
    capabilities: List[str]
    evidence_requirements: List[str]
    allowed_tools: List[str]
    handoff_targets: List[str]
    enabled: bool = True
    production_status: str = "analysis_only"


_AGENT_CLASSES: Dict[str, Type[BaseAgent]] = {
    "application": ApplicationAgent,
    "infrastructure": InfrastructureAgent,
    "kubernetes": KubernetesAgent,
    "security": SecurityAgent,
    "vm": VMAgent,
    "database": DatabaseAgent,
    "network": NetworkAgent,
    "storage": StorageAgent,
    "identity": IdentityAgent,
    "change": ChangeAgent,
}

_EVIDENCE_REQUIREMENTS: Dict[str, List[str]] = {
    "application": ["log", "metric"],
    "infrastructure": ["metric"],
    "kubernetes": ["log", "metric", "event_or_alert_recommended"],
    "security": ["log", "security_event_recommended"],
    "vm": ["metric", "log", "telemetry_recommended"],
}

_HANDOFF_TARGETS: Dict[str, List[str]] = {
    "application": ["change", "database", "security", "identity"],
    "infrastructure": ["network", "storage", "vm", "kubernetes"],
    "kubernetes": ["infrastructure", "network", "storage", "change", "application"],
    "security": ["identity", "application", "network"],
    "vm": ["infrastructure", "network", "storage"],
}


class AgentRegistry:
    def __init__(self, llm_adapter: Optional[LLMAdapter] = None):
        enabled = {name.strip().lower() for name in settings.AGENT_ENABLED_AGENTS}
        unknown = enabled.difference(_AGENT_CLASSES)
        if unknown:
            raise RuntimeError(f"unknown_enabled_agents:{sorted(unknown)}")
        self._agents = {
            name: cls(llm_adapter)
            for name, cls in _AGENT_CLASSES.items()
            if name in enabled
        }

    def get(self, name: str) -> Optional[BaseAgent]:
        return self._agents.get(name.lower())

    def enabled_names(self) -> List[str]:
        return sorted(self._agents)

    def manifests(self) -> List[AgentManifest]:
        result: List[AgentManifest] = []
        for name, agent in sorted(self._agents.items()):
            requirements = list(_EVIDENCE_REQUIREMENTS.get(name, []))
            handoffs = list(_HANDOFF_TARGETS.get(name, []))
            if isinstance(agent, DomainDiagnosticAgent):
                requirements = list(agent.spec.required_evidence_types)
                handoffs = list(agent.spec.default_handoffs)
            handoffs = [target for target in handoffs if target in _AGENT_CLASSES]
            result.append(AgentManifest(
                name=name,
                domain=name,
                version="1.0",
                description=agent.description,
                capabilities=[
                    "evidence_analysis",
                    "hypothesis_generation",
                    "conflict_detection",
                    "handoff",
                    "read_only_recommendation",
                    "human_escalation",
                ],
                evidence_requirements=requirements,
                allowed_tools=agent.allowed_tools,
                handoff_targets=handoffs,
                enabled=True,
            ))
        return result
