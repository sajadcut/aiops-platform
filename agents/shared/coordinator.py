from __future__ import annotations

from typing import Any, Dict, Iterable, List

from domain.contracts.config import settings


class IncidentCoordinator:
    """Deterministic coordinator for routing and multi-agent synthesis.

    It never changes policy, approves work, or executes actions. It selects
    specialists, requests bounded read-only evidence, and summarizes agreement,
    contradiction, uncertainty and escalation needs for RCA/Evaluator.
    """

    DOMAIN_EXPANSION = {
        "application": ["application", "change", "dependency", "database", "messaging"],
        "infrastructure": ["infrastructure", "network", "storage", "recovery"],
        "kubernetes": ["kubernetes", "infrastructure", "network", "storage", "change", "dependency"],
        "security": ["security", "identity", "application", "network"],
        "vm": ["vm", "infrastructure", "network", "storage", "recovery"],
        "database": ["database", "application", "storage", "infrastructure", "recovery", "dependency"],
        "network": ["network", "infrastructure", "application", "dependency"],
        "storage": ["storage", "infrastructure", "database", "recovery"],
        "identity": ["identity", "security", "application", "network", "dependency"],
        "change": ["change", "application", "kubernetes", "database", "dependency"],
        "dependency": ["dependency", "application", "database", "network", "identity", "messaging"],
        "messaging": ["messaging", "application", "network", "infrastructure", "dependency"],
        "recovery": ["recovery", "storage", "database", "infrastructure", "application"],
    }

    @classmethod
    def select_agents(cls, triage: Dict[str, Any], enabled: Iterable[str]) -> Dict[str, Any]:
        enabled_set = {str(name).lower() for name in enabled}
        requested = [str(x).lower() for x in (triage.get("handoff_agents") or [])]
        primary = str(triage.get("analysis_details", {}).get("primary_domain") or "").lower()
        ordered: List[str] = []

        def add(name: str) -> None:
            if name in enabled_set and name not in ordered:
                ordered.append(name)

        for name in requested:
            add(name)
        if primary:
            for name in cls.DOMAIN_EXPANSION.get(primary, [primary]):
                add(name)

        fallback = not ordered or float(triage.get("confidence", 0) or 0) < settings.AGENT_LOW_CONFIDENCE_THRESHOLD
        if fallback:
            for name in sorted(enabled_set):
                add(name)

        selected = ordered[: max(1, settings.AGENT_MAX_PARALLELISM)]
        skipped = sorted(enabled_set.difference(selected))
        reason = "fallback_broad_analysis" if fallback else "triage_specialist_routing"
        return {
            "selected": selected,
            "skipped": skipped,
            "reason": reason,
            "primary_domain": primary or "unknown",
            "requested_handoffs": requested,
        }

    @staticmethod
    def synthesize(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        valid = [f for f in findings if isinstance(f, dict) and f.get("agent_name")]
        severity_votes: Dict[str, int] = {}
        health_votes: Dict[str, int] = {}
        missing: List[str] = []
        handoffs: List[str] = []
        hypothesis_map: Dict[str, List[str]] = {}
        evidence_ids: set[str] = set()
        evidence_usage: Dict[str, Dict[str, List[str]]] = {}
        evidence_requests: List[Dict[str, Any]] = []
        weighted_confidence = 0.0
        confidence_weight = 0.0
        explicit_conflicts: List[Dict[str, Any]] = []

        for finding in valid:
            agent_name = str(finding.get("agent_name"))
            severity = str(finding.get("severity", "unknown")).lower()
            health = str(finding.get("health_status", "unknown")).lower()
            severity_votes[severity] = severity_votes.get(severity, 0) + 1
            health_votes[health] = health_votes.get(health, 0) + 1

            confidence = max(0.0, min(1.0, float(finding.get("confidence", 0) or 0)))
            coverage = max(0.0, min(1.0, float(finding.get("evidence_coverage", 0) or 0)))
            weight = max(0.1, coverage)
            weighted_confidence += confidence * weight
            confidence_weight += weight

            evidence_ids.update(str(x) for x in (finding.get("evidence_ids") or []))
            for item in finding.get("missing_evidence") or []:
                value = str(item)
                if value not in missing:
                    missing.append(value)
            for item in finding.get("handoff_agents") or []:
                value = str(item)
                if value not in handoffs:
                    handoffs.append(value)
            for request in finding.get("evidence_requests") or []:
                if not isinstance(request, dict) or not request.get("evidence_type"):
                    continue
                key = (str(request.get("evidence_type")), str(request.get("preferred_source") or ""))
                if not any((str(r.get("evidence_type")), str(r.get("preferred_source") or "")) == key for r in evidence_requests):
                    evidence_requests.append(request)
                if len(evidence_requests) >= settings.AGENT_MAX_DYNAMIC_EVIDENCE_TYPES:
                    break

            for hyp in finding.get("hypotheses") or []:
                if not isinstance(hyp, dict):
                    continue
                text = str(hyp.get("hypothesis", "")).strip().lower()
                if text:
                    hypothesis_map.setdefault(text, []).append(agent_name)
                supporting = [str(x) for x in (hyp.get("evidence_ids") or [])]
                conflicting = [str(x) for x in (hyp.get("conflicting_evidence_ids") or [])]
                if conflicting:
                    explicit_conflicts.append({
                        "agent": agent_name,
                        "hypothesis": str(hyp.get("hypothesis", "")),
                        "conflicting_evidence_ids": conflicting,
                    })
                for ref in supporting:
                    evidence_usage.setdefault(ref, {"support": [], "conflict": []})["support"].append(agent_name)
                for ref in conflicting:
                    evidence_usage.setdefault(ref, {"support": [], "conflict": []})["conflict"].append(agent_name)

        severity_non_unknown = {k: v for k, v in severity_votes.items() if k != "unknown"}
        health_non_unknown = {k: v for k, v in health_votes.items() if k != "unknown"}
        vote_disagreement = len(severity_non_unknown) > 1 or len(health_non_unknown) > 1
        cross_agent_evidence_conflicts = [
            {
                "evidence_id": ref,
                "supporting_agents": sorted(set(usage["support"])),
                "conflicting_agents": sorted(set(usage["conflict"])),
            }
            for ref, usage in evidence_usage.items()
            if usage["support"] and usage["conflict"]
        ]
        contradictions = explicit_conflicts + cross_agent_evidence_conflicts
        disagreement = vote_disagreement or bool(cross_agent_evidence_conflicts)

        shared_hypotheses = {k: v for k, v in hypothesis_map.items() if len(set(v)) > 1}
        consensus = sorted(shared_hypotheses, key=lambda key: len(set(shared_hypotheses[key])), reverse=True)

        def vote_agreement(votes: Dict[str, int]) -> float:
            total = sum(votes.values())
            return max(votes.values()) / total if total else 0.0

        severity_agreement = vote_agreement(severity_non_unknown)
        health_agreement = vote_agreement(health_non_unknown)
        agreement_components = [value for value in (severity_agreement, health_agreement) if value > 0]
        agreement_score = sum(agreement_components) / len(agreement_components) if agreement_components else 0.0
        if contradictions:
            agreement_score *= max(0.25, 1.0 - min(len(contradictions), 3) * settings.AGENT_CONFLICT_CONFIDENCE_PENALTY)

        confidence = weighted_confidence / confidence_weight if confidence_weight else 0.0
        if disagreement:
            confidence *= settings.AGENT_DISAGREEMENT_CONFIDENCE_FACTOR
        if missing:
            confidence *= settings.AGENT_MISSING_EVIDENCE_CONFIDENCE_FACTOR
        if contradictions:
            confidence *= max(0.25, 1.0 - min(len(contradictions), 3) * settings.AGENT_CONFLICT_CONFIDENCE_PENALTY)
        confidence = round(max(0.0, min(1.0, confidence)), 4)
        agreement_score = round(max(0.0, min(1.0, agreement_score)), 4)

        peer_review_targets = sorted({
            str(item.get("agent"))
            for item in explicit_conflicts
            if item.get("agent")
        })
        requires_human_review = disagreement or bool(contradictions) or bool(missing)
        second_opinion_required = (
            disagreement
            or bool(contradictions)
            or confidence < settings.AGENT_LOW_CONFIDENCE_THRESHOLD
        )

        return {
            "agents": [f.get("agent_name") for f in valid],
            "confidence": confidence,
            "agreement_score": agreement_score,
            "evidence_count": len(evidence_ids),
            "missing_evidence": missing,
            "evidence_requests": evidence_requests[: settings.AGENT_MAX_DYNAMIC_EVIDENCE_TYPES],
            "handoff_agents": handoffs,
            "disagreement": disagreement,
            "contradictions": contradictions,
            "peer_review_targets": peer_review_targets,
            "second_opinion_required": second_opinion_required,
            "severity_votes": severity_votes,
            "health_votes": health_votes,
            "consensus_hypotheses": consensus[: settings.AGENT_MAX_HYPOTHESES],
            "consensus_support": {
                hypothesis: sorted(set(shared_hypotheses[hypothesis]))
                for hypothesis in consensus[: settings.AGENT_MAX_HYPOTHESES]
            },
            "requires_human_review": requires_human_review,
        }
