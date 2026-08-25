from __future__ import annotations

from typing import Any, Dict, Iterable, List

from domain.contracts.config import settings


class IncidentCoordinator:
    """Deterministic coordinator for routing and multi-agent synthesis.

    It never changes policy, approves work, or executes actions. It only selects
    specialists and summarizes agreement, disagreement and evidence gaps.
    """

    DOMAIN_EXPANSION = {
        "application": ["application", "change", "database"],
        "infrastructure": ["infrastructure", "network", "storage"],
        "kubernetes": ["kubernetes", "infrastructure", "network", "storage", "change"],
        "security": ["security", "identity", "application"],
        "vm": ["vm", "infrastructure", "network", "storage"],
        "database": ["database", "application", "storage", "infrastructure"],
        "network": ["network", "infrastructure", "application"],
        "storage": ["storage", "infrastructure", "database"],
        "identity": ["identity", "security", "application"],
        "change": ["change", "application", "kubernetes", "database"],
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

        fallback = not ordered or triage.get("confidence", 0) < settings.AGENT_LOW_CONFIDENCE_THRESHOLD
        if fallback:
            for name in sorted(enabled_set):
                add(name)

        selected = ordered[: max(1, settings.AGENT_MAX_PARALLELISM)]
        skipped = sorted(enabled_set.difference(selected))
        reason = "fallback_broad_analysis" if fallback else "triage_specialist_routing"
        return {"selected": selected, "skipped": skipped, "reason": reason}

    @staticmethod
    def synthesize(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        valid = [f for f in findings if isinstance(f, dict) and f.get("agent_name")]
        severity_votes: Dict[str, int] = {}
        health_votes: Dict[str, int] = {}
        missing: List[str] = []
        handoffs: List[str] = []
        hypothesis_map: Dict[str, List[str]] = {}
        confidence_values: List[float] = []
        evidence_ids: set[str] = set()

        for finding in valid:
            severity = str(finding.get("severity", "unknown")).lower()
            health = str(finding.get("health_status", "unknown")).lower()
            severity_votes[severity] = severity_votes.get(severity, 0) + 1
            health_votes[health] = health_votes.get(health, 0) + 1
            confidence_values.append(float(finding.get("confidence", 0) or 0))
            evidence_ids.update(str(x) for x in (finding.get("evidence_ids") or []))
            for item in finding.get("missing_evidence") or []:
                if str(item) not in missing:
                    missing.append(str(item))
            for item in finding.get("handoff_agents") or []:
                if str(item) not in handoffs:
                    handoffs.append(str(item))
            for hyp in finding.get("hypotheses") or []:
                if not isinstance(hyp, dict):
                    continue
                text = str(hyp.get("hypothesis", "")).strip().lower()
                if text:
                    hypothesis_map.setdefault(text, []).append(str(finding.get("agent_name")))

        severity_non_unknown = [k for k in severity_votes if k != "unknown"]
        health_non_unknown = [k for k in health_votes if k != "unknown"]
        disagreement = len(severity_non_unknown) > 1 or len(health_non_unknown) > 1
        shared_hypotheses = {k: v for k, v in hypothesis_map.items() if len(set(v)) > 1}
        consensus = sorted(shared_hypotheses, key=lambda key: len(set(shared_hypotheses[key])), reverse=True)
        confidence = sum(confidence_values) / len(confidence_values) if confidence_values else 0.0
        if disagreement:
            confidence *= 0.75
        if missing:
            confidence *= 0.85
        return {
            "agents": [f.get("agent_name") for f in valid],
            "confidence": round(max(0.0, min(1.0, confidence)), 4),
            "evidence_count": len(evidence_ids),
            "missing_evidence": missing,
            "handoff_agents": handoffs,
            "disagreement": disagreement,
            "severity_votes": severity_votes,
            "health_votes": health_votes,
            "consensus_hypotheses": consensus[: settings.AGENT_MAX_HYPOTHESES],
            "requires_human_review": disagreement or bool(missing),
        }
