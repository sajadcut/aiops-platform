from typing import Any, Dict, List, Optional

from apps.evaluator.thresholds import DEFAULT_THRESHOLDS
from domain.contracts.config import settings


class EvaluationGate:
    """Deterministic quality gate between Agent/RCA output and Decision policy."""

    @classmethod
    def evaluate(
        cls,
        findings: List[Dict[str, Any]],
        plan: str,
        coordination: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        coordination = coordination or {}
        specialist_findings = [f for f in findings if isinstance(f, dict) and f.get("agent_name") != "triage"]
        confidences = [float(f.get("confidence", 0) or 0) for f in specialist_findings]
        max_confidence = max(confidences, default=0.0)
        evidence_ids = {str(e) for f in specialist_findings for e in (f.get("evidence_ids") or [])}
        evidence_count = len(evidence_ids)
        coverages = [float(f.get("evidence_coverage", 0) or 0) for f in specialist_findings]
        mean_coverage = sum(coverages) / len(coverages) if coverages else 0.0
        missing = sorted({str(e) for f in specialist_findings for e in (f.get("missing_evidence") or [])})
        unresolved_disagreement = bool(coordination.get("disagreement"))
        contradictions = list(coordination.get("contradictions") or [])
        agreement_score = float(coordination.get("agreement_score", 0) or 0)
        human_review = bool(coordination.get("requires_human_review")) or any(
            bool(f.get("requires_human_review")) for f in specialist_findings
        )
        specialist_failures = [
            str(f.get("agent_name"))
            for f in specialist_findings
            if str(f.get("finding_type", "")).endswith("_error")
            or "successful specialist analysis" in (f.get("missing_evidence") or [])
        ]

        unsafe_recommendations = []
        for finding in specialist_findings:
            for action in finding.get("recommended_actions") or []:
                if not isinstance(action, dict):
                    continue
                if not action.get("read_only", True) and not action.get("requires_approval", False):
                    unsafe_recommendations.append(action.get("action", "unknown"))

        hypothesis_without_evidence = False
        for finding in specialist_findings:
            for hypothesis in finding.get("hypotheses") or []:
                if isinstance(hypothesis, dict) and float(hypothesis.get("probability", 0) or 0) > settings.AGENT_LOW_CONFIDENCE_THRESHOLD:
                    if not hypothesis.get("evidence_ids"):
                        hypothesis_without_evidence = True

        blockers = []
        if not specialist_findings:
            blockers.append("no_specialist_analysis")
        if not plan.strip():
            blockers.append("empty_plan")
        if specialist_failures:
            blockers.append("specialist_failure")
        if max_confidence < DEFAULT_THRESHOLDS.minimum_confidence:
            blockers.append("low_confidence")
        if evidence_count < DEFAULT_THRESHOLDS.minimum_evidence:
            blockers.append("insufficient_evidence")
        if mean_coverage < settings.AGENT_MIN_EVIDENCE_COVERAGE:
            blockers.append("low_evidence_coverage")
        if hypothesis_without_evidence:
            blockers.append("ungrounded_hypothesis")
        if unsafe_recommendations:
            blockers.append("unsafe_agent_recommendation")
        if unresolved_disagreement:
            blockers.append("unresolved_agent_disagreement")
        if contradictions:
            blockers.append("unresolved_evidence_conflict")
        if len(specialist_findings) > 1 and agreement_score < settings.AGENT_MIN_CONSENSUS_SCORE:
            blockers.append("low_agent_consensus")
        if missing:
            blockers.append("critical_missing_evidence")
        if human_review:
            blockers.append("human_review_required")

        # Preserve deterministic blocker ordering while removing duplicates.
        blockers = list(dict.fromkeys(blockers))
        approved = not blockers
        return {
            "approved_for_decision": approved,
            "confidence": max_confidence,
            "evidence_count": evidence_count,
            "evidence_coverage": round(mean_coverage, 4),
            "agreement_score": round(agreement_score, 4),
            "missing_evidence": missing,
            "disagreement": unresolved_disagreement,
            "contradictions": contradictions,
            "specialist_failures": specialist_failures,
            "human_review_required": human_review,
            "unsafe_recommendations": unsafe_recommendations,
            "blockers": blockers,
            "reason": "evaluation_passed" if approved else blockers[0],
        }
