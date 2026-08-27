"""Catalog canonical Agentهای تخصصی و capability/handoff آنها.

این registry با ToolRegistry اجرایی فرق دارد: Agentها فقط تحلیل، hypothesis و recommendation
تولید می‌کنند و `production_status=analysis_only` دارند. orchestration از manifestها برای
routing و همکاری استفاده می‌کند، نه برای اعطای write authority.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional, Type

from agents.application import ApplicationAgent
from agents.change import ChangeAgent
from agents.database import DatabaseAgent
from agents.dependency import DependencyAgent
from agents.identity import IdentityAgent
from agents.infrastructure import InfrastructureAgent
from agents.kubernetes import KubernetesAgent
from agents.messaging import MessagingAgent
from agents.network import NetworkAgent
from agents.recovery import RecoveryAgent
from agents.security import SecurityAgent
from agents.shared.base import BaseAgent
from agents.shared.domain_agent import DomainDiagnosticAgent
from agents.storage import StorageAgent
from agents.vm import VMAgent
from domain.contracts.config import settings
from integrations.llm.base import LLMAdapter


@dataclass(frozen=True)
class AgentManifest:
    """Metadata قابل مشاهده برای routing/UI: domain، evidence نیازمند و handoffهای مجاز."""

    name: str
    domain: str
    version: str
    description: str
    capabilities: List[str]
    evidence_requirements: List[str]
    allowed_tools: List[str]
    handoff_targets: List[str]
    enabled: bool
    production_status: str = "analysis_only"


# فقط کلاس‌های حاضر در این allow-list می‌توانند با نام config وارد runtime شوند.
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
    "dependency": DependencyAgent,
    "messaging": MessagingAgent,
    "recovery": RecoveryAgent,
}

# این requirements routing اولیه را راهنمایی می‌کنند. نبود evidence باید در Finding به
# شکل missing/source unavailable دیده شود، نه اینکه Agent آن را healthy فرض کند.
_EVIDENCE_REQUIREMENTS: Dict[str, List[str]] = {
    "application": ["log", "metric"],
    "infrastructure": ["metric"],
    "kubernetes": ["log", "metric", "event_or_alert_recommended"],
    "security": ["log", "security_event_recommended"],
    "vm": ["metric", "log", "telemetry_recommended"],
    "database": ["metric", "log"],
    "network": ["metric"],
    "storage": ["metric"],
    "identity": ["log"],
    "change": ["log"],
    "dependency": ["metric", "log"],
    "messaging": ["metric", "log"],
    "recovery": ["log", "metric"],
}

# Handoff یعنی درخواست تحلیل مکمل از specialist دیگر؛ به معنی delegation اجرای write نیست.
_HANDOFF_TARGETS: Dict[str, List[str]] = {
    "application": ["change", "database", "dependency", "messaging", "security", "identity"],
    "infrastructure": ["network", "storage", "vm", "kubernetes", "recovery"],
    "kubernetes": ["infrastructure", "network", "storage", "change", "application", "dependency"],
    "security": ["identity", "application", "network"],
    "vm": ["infrastructure", "network", "storage", "recovery"],
    "database": ["application", "storage", "infrastructure", "recovery", "dependency"],
    "network": ["infrastructure", "application", "identity", "dependency"],
    "storage": ["infrastructure", "database", "kubernetes", "recovery"],
    "identity": ["security", "application", "network", "dependency"],
    "change": ["application", "kubernetes", "database", "dependency"],
    "dependency": ["application", "database", "network", "identity", "messaging"],
    "messaging": ["application", "network", "infrastructure", "dependency"],
    "recovery": ["storage", "database", "infrastructure", "application"],
}


class AgentRegistry:
    """Agentهای analysis-only فعال را بر اساس `.env` instantiate و manifest آنها را ارائه می‌کند."""

    def __init__(self, llm_adapter: Optional[LLMAdapter] = None):
        enabled = {name.strip().lower() for name in settings.AGENT_ENABLED_AGENTS}
        unknown = enabled.difference(_AGENT_CLASSES)
        # typo در AGENT_ENABLED_AGENTS به silent disable تبدیل نمی‌شود؛ startup fail می‌شود.
        if unknown:
            raise RuntimeError(f"unknown_enabled_agents:{sorted(unknown)}")
        self._llm_adapter = llm_adapter
        self._enabled_names = enabled
        self._agents = {
            name: cls(llm_adapter)
            for name, cls in _AGENT_CLASSES.items()
            if name in enabled
        }

    def get(self, name: str) -> Optional[BaseAgent]:
        """Agent فعال را برای routing برمی‌گرداند؛ disabled Agent اجرا نمی‌شود."""
        return self._agents.get(name.lower())

    def enabled_names(self) -> List[str]:
        """نام Agentهای واقعاً فعال runtime را برمی‌گرداند."""
        return sorted(self._agents)

    def known_names(self) -> List[str]:
        """همه Agentهای شناخته‌شده codebase، مستقل از enable/disable config."""
        return sorted(_AGENT_CLASSES)

    def manifests(self, include_disabled: bool = True) -> List[AgentManifest]:
        """Catalog قابل مصرف توسط Dashboard/orchestrator را بدون افشای write authority می‌سازد."""
        result: List[AgentManifest] = []
        names = self.known_names() if include_disabled else self.enabled_names()
        for name in names:
            enabled = name in self._enabled_names
            agent = self._agents.get(name)
            if agent is None:
                # برای نمایش manifest Agent disabled نمونه ساخته می‌شود اما وارد runtime routing نمی‌شود.
                agent = _AGENT_CLASSES[name](self._llm_adapter)
            requirements = list(_EVIDENCE_REQUIREMENTS.get(name, []))
            handoffs = list(_HANDOFF_TARGETS.get(name, []))
            if isinstance(agent, DomainDiagnosticAgent):
                requirements = list(agent.spec.required_evidence_types)
                handoffs = list(agent.spec.default_handoffs)
            handoffs = [target for target in handoffs if target in _AGENT_CLASSES]
            capabilities = [
                "evidence_analysis",
                "hypothesis_generation",
                "conflict_detection",
                "falsification_planning",
                "handoff",
                "read_only_recommendation",
                "human_escalation",
                "rag_auxiliary_context",
                "memory_auxiliary_context",
            ]
            result.append(AgentManifest(
                name=name,
                domain=name,
                version="2.0",
                description=agent.description,
                capabilities=capabilities,
                evidence_requirements=requirements,
                allowed_tools=agent.allowed_tools,
                handoff_targets=handoffs,
                enabled=enabled,
                production_status="analysis_only",
            ))
        return result
