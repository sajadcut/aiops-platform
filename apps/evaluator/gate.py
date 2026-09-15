"""Evaluator قطعی بین reasoning Agentها و Decision Engine.

این لایه عمداً deterministic است: حتی اگر LLM/Agent پیشنهاد قانع‌کننده‌ای بدهد، نبود
Evidence، confidence پایین، disagreement یا recommendation ناامن باید Decision را block
کند. در نتیجه LLM نمی‌تواند با متن خود این gate را دور بزند.
"""

from typing import Any, Dict, List, Optional

from apps.evaluator.thresholds import DEFAULT_THRESHOLDS
from domain.contracts.config import settings


class EvaluationGate:
    """کیفیت RCA را از روی Evidence/Consensus/Safety به‌صورت fail-closed ارزیابی می‌کند."""

    @staticmethod
    def _specialist_failed(finding: Dict[str, Any]) -> bool:
        if str(finding.get("finding_type", "")).endswith("_error"):
            return True
        for missing in finding.get("missing_evidence") or []:
            text = " ".join(str(missing).strip().lower().split())
            if text == "successful specialist analysis" or text.startswith("successful structured"):
                return True
        return False

    @staticmethod
    def _governed_deterministic_recovery(finding: Dict[str, Any]) -> bool:
        """Return true only for an evidence-grounded, approval-bound stopped-service recovery.

        This narrow escape hatch separates uncertainty about *why* a service stopped
        from certainty about its current operational state. It never authorizes a
        write: Decision, Approval, Capability, fresh precondition validation and
        post-action verification remain mandatory downstream.
        """
        details = finding.get("analysis_details") or {}
        if not isinstance(details, dict) or details.get("deterministic_fault") != "service_stopped":
            return False
        if float(finding.get("confidence", 0) or 0) < DEFAULT_THRESHOLDS.minimum_confidence:
            return False
        if len(finding.get("evidence_ids") or []) < 3:
            return False
        for action in finding.get("recommended_actions") or []:
            if not isinstance(action, dict):
                continue
            if (
                str(action.get("action") or "") == "start_service"
                and action.get("read_only") is False
                and action.get("requires_approval") is True
                and str(action.get("suggested_tool") or "") == "ssh_vm"
            ):
                return True
        return False

    @classmethod
    def evaluate(
        cls,
        findings: List[Dict[str, Any]],
        plan: str,
        coordination: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        coordination = coordination or {}

        # Triage فقط routing اولیه است و نباید به‌عنوان specialist evidence باعث بالا رفتن
        # confidence یا coverage ارزیابی نهایی شود.
        all_specialists = [
            f for f in findings
            if isinstance(f, dict) and f.get("agent_name") != "triage"
        ]
        failed_findings = [f for f in all_specialists if cls._specialist_failed(f)]
        grounded_findings = [f for f in all_specialists if not cls._specialist_failed(f)]
        # Partial LLM/specialist failure is a degraded condition, not a reason to
        # discard authoritative evidence from another grounded specialist. If all
        # specialists fail, we still evaluate the failed rows and fail closed.
        specialist_findings = grounded_findings or all_specialists
        specialist_failures = [str(f.get("agent_name")) for f in failed_findings]
        degraded_specialist_analysis = bool(grounded_findings and failed_findings)
        deterministic_recoveries = [
            f for f in grounded_findings if cls._governed_deterministic_recovery(f)
        ]
        operational_state_resolved = bool(deterministic_recoveries)

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

        # Agent فقط می‌تواند action پیشنهاد کند. اگر write recommendation بدون approval
        # requirement ظاهر شود، evaluator آن را unsafe می‌داند و flow را متوقف می‌کند.
        unsafe_recommendations = []
        for finding in specialist_findings:
            for action in finding.get("recommended_actions") or []:
                if not isinstance(action, dict):
                    continue
                if not action.get("read_only", True) and not action.get("requires_approval", False):
                    unsafe_recommendations.append(action.get("action", "unknown"))

        # hypothesis با probability بالا ولی بدون Evidence ID یک ادعای ungrounded است.
        hypothesis_without_evidence = False
        for finding in specialist_findings:
            for hypothesis in finding.get("hypotheses") or []:
                if isinstance(hypothesis, dict) and float(hypothesis.get("probability", 0) or 0) > settings.AGENT_LOW_CONFIDENCE_THRESHOLD:
                    if not hypothesis.get("evidence_ids"):
                        hypothesis_without_evidence = True

        blockers = []
        advisories = []
        if not all_specialists:
            blockers.append("no_specialist_analysis")
        if not plan.strip():
            blockers.append("empty_plan")
        # A failed specialist blocks only when there is no grounded specialist to
        # carry the RCA. This keeps fail-closed behavior for total analysis loss.
        if failed_findings and not grounded_findings:
            blockers.append("specialist_failure")
        if max_confidence < DEFAULT_THRESHOLDS.minimum_confidence:
            blockers.append("low_confidence")
        if evidence_count < DEFAULT_THRESHOLDS.minimum_evidence:
            blockers.append("insufficient_evidence")
        if mean_coverage < settings.AGENT_MIN_EVIDENCE_COVERAGE:
            blockers.append("low_evidence_coverage")
        if hypothesis_without_evidence:
            (advisories if operational_state_resolved else blockers).append("ungrounded_hypothesis")
        if unsafe_recommendations:
            blockers.append("unsafe_agent_recommendation")

        # If a VM specialist has deterministically proven the current stopped-service
        # state and the only proposed write is approval-bound start_service, disputes
        # about historical/root cause remain visible but no longer prevent reaching
        # the Decision/Approval gate. Fresh execution preconditions still fail closed.
        if unresolved_disagreement:
            (advisories if operational_state_resolved else blockers).append("unresolved_agent_disagreement")
        if contradictions:
            (advisories if operational_state_resolved else blockers).append("unresolved_evidence_conflict")
        if len(specialist_findings) > 1 and agreement_score < settings.AGENT_MIN_CONSENSUS_SCORE:
            (advisories if operational_state_resolved else blockers).append("low_agent_consensus")
        if missing:
            (advisories if operational_state_resolved else blockers).append("critical_missing_evidence")
        if human_review:
            (advisories if operational_state_resolved else blockers).append("human_review_required")

        blockers = list(dict.fromkeys(blockers))
        advisories = list(dict.fromkeys(advisories))
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
            "degraded_specialist_analysis": degraded_specialist_analysis,
            "grounded_specialists": [str(f.get("agent_name")) for f in grounded_findings],
            "operational_state_resolved": operational_state_resolved,
            "deterministic_recovery_agents": [str(f.get("agent_name")) for f in deterministic_recoveries],
            "human_review_required": human_review,
            "unsafe_recommendations": unsafe_recommendations,
            "non_blocking_advisories": advisories,
            "blockers": blockers,
            "reason": "evaluation_passed" if approved else blockers[0],
        }