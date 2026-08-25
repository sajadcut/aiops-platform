from __future__ import annotations

from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

from domain.contracts.config import settings
from integrations.llm.base import LLMAdapter
from integrations.llm.openai_compatible import configured_llm_adapter


class AgentInput(BaseModel):
    """Standard, evidence-first input passed to every operational agent."""

    incident_id: Optional[str] = None
    evidence_summary: str = Field(..., description="Human/machine summary of known evidence")
    service_name: Optional[str] = None
    time_range: Optional[Dict[str, str]] = None
    context: Dict[str, Any] = Field(default_factory=dict)


class OperationalHypothesis(BaseModel):
    hypothesis: str
    probability: float = Field(ge=0, le=1)
    evidence_ids: List[str] = Field(default_factory=list)
    falsification_checks: List[str] = Field(default_factory=list)


class RecommendedAction(BaseModel):
    action: str
    purpose: str = "investigation"
    risk_level: str = "low"
    requires_approval: bool = False
    read_only: bool = True
    suggested_tool: Optional[str] = None


class AgentOutput(BaseModel):
    """Auditable output contract for NOC/SRE/SOC operational analysis."""

    agent_name: str
    finding_type: str
    statement: str
    confidence: float = Field(ge=0, le=1)
    severity: str = "unknown"
    health_status: str = "unknown"
    evidence_ids: List[str] = Field(default_factory=list)
    evidence_count: int = 0
    recommendations: List[str] = Field(default_factory=list)
    recommended_actions: List[RecommendedAction] = Field(default_factory=list)
    hypotheses: List[OperationalHypothesis] = Field(default_factory=list)
    missing_evidence: List[str] = Field(default_factory=list)
    handoff_agents: List[str] = Field(default_factory=list)
    affected_components: List[str] = Field(default_factory=list)
    blast_radius: str = "unknown"
    requires_approval: bool = False
    requires_human_review: bool = False
    analysis_details: Dict[str, Any] = Field(default_factory=dict)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class BaseAgent(ABC):
    """Base contract for analysis-only specialized agents.

    Agents may inspect evidence and recommend controlled actions. They never
    execute write operations; all mutation remains behind Decision/Approval/
    Execution Service boundaries.
    """

    def __init__(self, llm_adapter: Optional[LLMAdapter] = None):
        self.llm = llm_adapter or configured_llm_adapter()

    @property
    @abstractmethod
    def name(self) -> str:
        raise NotImplementedError

    @property
    @abstractmethod
    def description(self) -> str:
        raise NotImplementedError

    @property
    def allowed_tools(self) -> List[str]:
        """Read-only evidence tools the agent may request through orchestration."""
        return []

    @abstractmethod
    async def analyze(self, input_data: AgentInput) -> AgentOutput:
        raise NotImplementedError

    async def validate_input(self, input_data: AgentInput) -> bool:
        return bool(input_data.evidence_summary.strip() or self.evidence_items(input_data))

    @staticmethod
    def evidence_items(input_data: AgentInput) -> List[Dict[str, Any]]:
        raw = input_data.context.get("evidence", []) if input_data.context else []
        if not isinstance(raw, list):
            return []
        return [item for item in raw if isinstance(item, dict)][: settings.AGENT_MAX_EVIDENCE_ITEMS]

    @classmethod
    def evidence_ids(cls, input_data: AgentInput) -> List[str]:
        ids: List[str] = []
        for item in cls.evidence_items(input_data):
            ref = item.get("evidence_id") or item.get("id") or item.get("reference") or item.get("source_id")
            if ref is not None:
                value = str(ref)
                if value not in ids:
                    ids.append(value)
        return ids

    @staticmethod
    def safe_confidence(value: Any, evidence_count: int) -> float:
        try:
            confidence = max(0.0, min(1.0, float(value)))
        except (TypeError, ValueError):
            confidence = 0.0
        if evidence_count < settings.AGENT_MIN_EVIDENCE_ITEMS:
            confidence = min(confidence, settings.AGENT_LOW_CONFIDENCE_THRESHOLD)
        return confidence

    @staticmethod
    def normalize_list(value: Any, limit: int = 5) -> List[str]:
        if value is None:
            return []
        if isinstance(value, str):
            value = [value]
        if not isinstance(value, list):
            return []
        result: List[str] = []
        for item in value:
            text = str(item).strip()
            if text and text not in result:
                result.append(text)
            if len(result) >= limit:
                break
        return result

    @staticmethod
    def missing_evidence_for(input_data: AgentInput, required_types: List[str]) -> List[str]:
        evidence = BaseAgent.evidence_items(input_data)
        available_types = {str(item.get("type", "")).lower() for item in evidence}
        return [f"{kind} evidence" for kind in required_types if kind.lower() not in available_types]

    def human_review_required(self, confidence: float, missing_evidence: List[str], severe: bool = False) -> bool:
        return severe or confidence < settings.AGENT_LOW_CONFIDENCE_THRESHOLD or bool(missing_evidence)

    @staticmethod
    def analysis_only_actions(actions: List[str], suggested_tool: Optional[str] = None) -> List[RecommendedAction]:
        return [
            RecommendedAction(
                action=action,
                purpose="investigation",
                risk_level="low",
                requires_approval=False,
                read_only=True,
                suggested_tool=suggested_tool,
            )
            for action in actions[: settings.AGENT_MAX_RECOMMENDATIONS]
        ]
