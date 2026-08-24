from typing import Any, Dict, List
from pydantic import BaseModel, Field


class EvaluationResult(BaseModel):
    accepted: bool
    confidence: float = Field(ge=0.0, le=1.0)
    evidence_coverage: float = Field(ge=0.0, le=1.0)
    issues: List[str] = Field(default_factory=list)
    recommendation: str


class PlanEvaluator:
    """Guardrail between RCA and DecisionEngine."""

    MIN_CONFIDENCE = 0.60

    @classmethod
    def evaluate(cls, plan: str, findings: List[Dict[str, Any]]) -> EvaluationResult:
        confidence_values = [
            float(f["confidence"])
            for f in findings
            if isinstance(f, dict) and isinstance(f.get("confidence"), (int, float))
        ]
        confidence = sum(confidence_values) / len(confidence_values) if confidence_values else 0.0
        evidence_claims = [f for f in findings if isinstance(f, dict) and f.get("evidence_ids")]
        coverage = len(evidence_claims) / max(len(findings), 1)
        issues: List[str] = []
        if not plan.strip():
            issues.append("empty_plan")
        if confidence < cls.MIN_CONFIDENCE:
            issues.append("low_confidence")
        if coverage < 0.5:
            issues.append("insufficient_evidence_coverage")
        accepted = not issues
        return EvaluationResult(
            accepted=accepted,
            confidence=confidence,
            evidence_coverage=coverage,
            issues=issues,
            recommendation="proceed_to_decision" if accepted else "human_review_required",
        )
