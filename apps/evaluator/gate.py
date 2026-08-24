from typing import Any, Dict, List
from apps.evaluator.thresholds import DEFAULT_THRESHOLDS

class EvaluationGate:
    @classmethod
    def evaluate(cls, findings: List[Dict[str, Any]], plan: str) -> Dict[str, Any]:
        confidences = [float(f.get("confidence", 0)) for f in findings if isinstance(f, dict)]
        max_confidence = max(confidences, default=0.0)
        evidence_count = len({str(e) for f in findings for e in (f.get("evidence_ids") or [])})
        approved = bool(plan.strip()) and max_confidence >= DEFAULT_THRESHOLDS.minimum_confidence and evidence_count >= DEFAULT_THRESHOLDS.minimum_evidence
        return {"approved_for_decision": approved, "confidence": max_confidence, "evidence_count": evidence_count,
                "reason": "evaluation_passed" if approved else "insufficient_evidence_or_confidence"}
