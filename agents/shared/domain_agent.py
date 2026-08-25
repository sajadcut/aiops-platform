from __future__ import annotations

import json
from dataclasses import dataclass
from typing import List, Optional

from agents.shared.base import AgentInput, AgentOutput, BaseAgent, OperationalHypothesis
from domain.contracts.config import settings
from domain.contracts.logging import logger
from integrations.llm.base import LLMAdapter


@dataclass(frozen=True)
class DomainSpec:
    name: str
    description: str
    focus: List[str]
    required_evidence_types: List[str]
    read_tools: List[str]
    default_handoffs: List[str]


class DomainDiagnosticAgent(BaseAgent):
    """Reusable specialist implementation for evidence-grounded operational domains."""

    spec: DomainSpec

    def __init__(self, llm_adapter: Optional[LLMAdapter] = None):
        super().__init__(llm_adapter)

    @property
    def name(self) -> str:
        return self.spec.name

    @property
    def description(self) -> str:
        return self.spec.description

    @property
    def allowed_tools(self) -> List[str]:
        return list(self.spec.read_tools)

    async def analyze(self, input_data: AgentInput) -> AgentOutput:
        evidence = self.evidence_items(input_data)
        evidence_ids = self.evidence_ids(input_data)
        auxiliary = self.auxiliary_context(input_data)
        missing = self.missing_evidence_for(input_data, self.spec.required_evidence_types)
        prompt = f"""You are the {self.name} specialist in a production AIOps platform.
LIVE EVIDENCE is authoritative. RAG and Memory are auxiliary only. Never invent current state.
Focus areas: {json.dumps(self.spec.focus)}
Return one JSON object with keys: severity, health_status, findings, affected_components,
probable_dependencies, blast_radius, hypotheses, missing_evidence, handoff_agents,
immediate_checks, escalation_target, risk_level, uncertainty_reason, confidence.
Each hypothesis: hypothesis, probability, evidence_ids, conflicting_evidence_ids,
falsification_checks, impacted_components, recommended_next_evidence.
Only cite LIVE EVIDENCE IDs. immediate_checks are read-only.
Incident={input_data.incident_id}\nService={input_data.service_name}\nSummary={input_data.evidence_summary}
LIVE_EVIDENCE={json.dumps(evidence, default=str)}
AUXILIARY_CONTEXT={json.dumps(auxiliary, default=str)}"""
        try:
            result = await self.generate_structured(prompt)
        except Exception as exc:
            logger.error(f"{self.name} structured analysis failed: {exc}")
            result = {
                "severity": "unknown", "health_status": "unknown", "findings": [],
                "affected_components": [], "probable_dependencies": [], "blast_radius": "unknown",
                "hypotheses": [], "missing_evidence": ["successful structured specialist analysis"],
                "handoff_agents": self.spec.default_handoffs, "immediate_checks": [f"Collect {self.name} evidence"],
                "escalation_target": f"{self.name}-operator", "risk_level": "low",
                "uncertainty_reason": "structured_analysis_failed", "confidence": 0.0,
            }
        all_missing = sorted(set(missing + self.normalize_list(result.get("missing_evidence"), 8)))
        hypotheses: List[OperationalHypothesis] = []
        conflicts = 0
        for item in result.get("hypotheses", [])[: settings.AGENT_MAX_HYPOTHESES]:
            if not isinstance(item, dict) or not item.get("hypothesis"):
                continue
            conflicting = [str(x) for x in item.get("conflicting_evidence_ids", []) if str(x) in evidence_ids]
            conflicts += len(conflicting)
            hypotheses.append(OperationalHypothesis(
                hypothesis=str(item["hypothesis"]),
                probability=self.safe_confidence(item.get("probability", 0), len(evidence), all_missing, len(conflicting)),
                evidence_ids=[str(x) for x in item.get("evidence_ids", []) if str(x) in evidence_ids],
                conflicting_evidence_ids=conflicting,
                falsification_checks=self.normalize_list(item.get("falsification_checks"), 5),
                impacted_components=self.normalize_list(item.get("impacted_components"), 6),
                recommended_next_evidence=self.normalize_list(item.get("recommended_next_evidence"), 6),
            ))
        confidence = self.safe_confidence(result.get("confidence"), len(evidence), all_missing, conflicts)
        findings = self.normalize_list(result.get("findings"), 10)
        actions = self.normalize_list(result.get("immediate_checks"), settings.AGENT_MAX_RECOMMENDATIONS)
        coverage = self.evidence_coverage(len(evidence), all_missing)
        return AgentOutput(
            agent_name=self.name,
            finding_type=f"{self.name}_analysis",
            statement=(f"{self.name.title()} evidence: " + ("; ".join(findings) if findings else "no confirmed domain fault yet"))[:600],
            severity=str(result.get("severity", "unknown")).lower(),
            health_status=str(result.get("health_status", "unknown")).lower(),
            confidence=confidence,
            evidence_ids=evidence_ids,
            evidence_count=len(evidence),
            evidence_coverage=coverage,
            findings=findings,
            recommendations=actions,
            recommended_actions=self.analysis_only_actions(actions, self.spec.read_tools[0] if self.spec.read_tools else None),
            hypotheses=hypotheses,
            missing_evidence=all_missing,
            handoff_agents=self.normalize_list(result.get("handoff_agents"), 6) or self.spec.default_handoffs,
            probable_dependencies=self.normalize_list(result.get("probable_dependencies"), 8),
            affected_components=self.normalize_list(result.get("affected_components"), 8),
            blast_radius=str(result.get("blast_radius", "unknown")),
            escalation_target=str(result.get("escalation_target") or f"{self.name}-operator"),
            risk_level=str(result.get("risk_level", "low")).lower(),
            uncertainty_reason=str(result.get("uncertainty_reason") or ("missing_evidence" if all_missing else "")) or None,
            requires_human_review=self.human_review_required(confidence, all_missing),
            analysis_details={
                "focus": self.spec.focus,
                "knowledge_context_count": len(auxiliary["knowledge_rag"]),
                "memory_context_count": len(auxiliary["operational_memory"]),
                "conflicting_evidence_count": conflicts,
            },
            model_metadata=self._last_model_metadata,
        )
