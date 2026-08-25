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
            result.append(AgentManifest(
                name=name,
                domain=name,
                version="1.0",
                description=agent.description,
                capabilities=["evidence_analysis", "hypothesis_generation", "handoff", "read_only_recommendation"],
                evidence_requirements=[],
                allowed_tools=agent.allowed_tools,
                handoff_targets=[],
            ))
        return result
