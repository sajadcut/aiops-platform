import json
from typing import List, Optional

from agents.shared.base import AgentInput, AgentOutput, BaseAgent, OperationalHypothesis
from agents.shared.intelligence import build_deterministic_analysis, prompt_evidence_projection, sanitize_prompt_value
from agents.triage.engine import build_triage_decision_support
from domain.contracts.config import settings
from domain.contracts.logging import logger
from integrations.llm.base import LLMAdapter


class TriageAgent(BaseAgent):
    def __init__(self, llm_adapter: Optional[LLMAdapter] = None):
        super().__init__(llm_adapter)

    @property
    def name(self) -> str:
        return "triage"

    @property
    def description(self) -> str:
        return "Production incident triage: correlate signals, separate symptom/causal layers, score evidence gaps and route bounded specialist analysis"

    @property
    def allowed_tools(self) -> List[str]:
        return ["zabbix_read", "elasticsearch_logs", "prometheus_query", "kubectl_get", "vm_telemetry", "knowledge_search"]

    @staticmethod
    def _legacy_asset_routes(asset: dict) -> List[str]:
        """Preserve the historical handoff contract while runtime uses focused specialist_routes."""
        asset_type = str(asset.get("asset_type") or "unknown").lower()
        platform = str(asset.get("platform") or "unknown").lower()
        if platform == "kubernetes" or "kubernetes" in asset_type:
            return ["kubernetes", "infrastructure"]
        if asset_type == "database":
            return ["database", "application", "dependency", "infrastructure"]
        if asset_type == "network":
            return ["network", "infrastructure", "dependency"]
        if asset_type == "vm" or platform == "vm" or str(asset.get("os_family") or "unknown").lower() in {"linux", "windows"}:
            return ["vm", "infrastructure", "network"]
        return []

    async def analyze(self, input_data: AgentInput) -> AgentOutput:
        logger.info(f"TriageAgent analyzing: {input_data.incident_id}")
        context = input_data.context or {}
        raw_evidence = context.get("evidence", []) if isinstance(context.get("evidence", []), list) else []
        evidence = self.evidence_items(input_data)
        stale_ids = self.stale_evidence_ids(input_data)
        prompt_evidence = prompt_evidence_projection(evidence, settings.AGENT_MAX_EVIDENCE_ITEMS)
        deterministic = build_deterministic_analysis("triage", evidence, service_name=input_data.service_name)
        evidence_ids = self.evidence_ids(input_data)
        auxiliary = self.auxiliary_context(input_data)
        live = context.get("live_evidence", {})
        asset = context.get("asset_context") or (live.get("asset_context", {}) if isinstance(live, dict) else {}) or {}
        topology_context = context.get("topology_context", {}) if isinstance(context.get("topology_context", {}), dict) else {}

        valid_routes = {str(name).lower() for name in settings.AGENT_ENABLED_AGENTS}
        decision = build_triage_decision_support(
            fresh_evidence=evidence,
            raw_evidence=raw_evidence,
            stale_ids=stale_ids,
            asset=asset,
            topology=topology_context,
            context=context,
            enabled_domains=valid_routes,
            max_routes=max(1, settings.AGENT_MAX_PARALLELISM),
        )

        type_counts = {}
        source_counts = {}
        for item in evidence:
            kind = str(item.get("type", "unknown")).lower()
            source = str(item.get("source", "unknown")).lower()
            type_counts[kind] = type_counts.get(kind, 0) + 1
            source_counts[source] = source_counts.get(source, 0) + 1

        domains = [
            "application", "infrastructure", "kubernetes", "security", "vm",
            "database", "network", "storage", "identity", "change",
            "dependency", "messaging", "recovery", "unknown",
        ]
        prompt = f"""You are the ambiguity-resolution and hypothesis-synthesis stage for a production incident triage engine. LIVE EVIDENCE is authoritative. RAG/Memory are auxiliary pattern suggestions only and never proof of this incident. ASSET_CONTEXT may contain Cognia-assisted topology hints when live metadata was incomplete. Inspect field_provenance and requires_live_verification: knowledge-sourced identity can guide read-only evidence collection but is not live proof and cannot authorize a write. Live fields win over Cognia on conflict.
TRIAGE_DECISION_SUPPORT is deterministic and owns strong routing/impact guardrails. Do not override a well-supported causal route merely because the alert text or asset type names a different symptom layer. Your role is to resolve residual ambiguity, generate falsifiable hypotheses and concise findings. Distinguish observed symptom, affected layer and probable causal layer. A prior incident can suggest a pattern but cannot establish current causality.
Classify primary_domain from {domains}. Return secondary_domains only when supported by current evidence. Do not copy alert severity blindly; customer impact, affected services/hosts, redundancy, duration, SLO impact and blast radius matter.
Return JSON keys: primary_domain, secondary_domains, severity, health_status, urgency_reason, findings, affected_components, probable_dependencies, blast_radius, hypotheses, missing_evidence, evidence_gaps, next_best_evidence, specialist_routes, route_reasons, rejected_routes, immediate_checks, escalation_target, risk_level, uncertainty_reason, confidence.
Hypotheses: hypothesis, probability, evidence_ids, conflicting_evidence_ids, falsification_checks, impacted_components, recommended_next_evidence. Only current live evidence IDs may be cited.
Never invent a VM, OS, Kubernetes workload, deployment, compromise, outage, DB failure, packet loss, queue backlog, recovery failure or metric. immediate_checks are read-only evidence collection.
Incident={input_data.incident_id}\nService={input_data.service_name}\nSummary={input_data.evidence_summary}\nTRIAGE_DECISION_SUPPORT={json.dumps(sanitize_prompt_value(decision), default=str)}\nDETERMINISTIC_ANALYSIS={json.dumps(deterministic, default=str)}\nASSET_CONTEXT={json.dumps(sanitize_prompt_value(asset), default=str)}\nTOPOLOGY_CONTEXT={json.dumps(sanitize_prompt_value(topology_context), default=str)}\nLIVE_EVIDENCE={json.dumps(prompt_evidence, default=str)}\nAUXILIARY_CONTEXT={json.dumps(sanitize_prompt_value(auxiliary), default=str)}\nContextSummary={json.dumps(sanitize_prompt_value(context.get('summary', {})), default=str)}"""
        try:
            result = await self.generate_structured(prompt)
        except Exception as exc:
            logger.error(f"TriageAgent analysis failed: {exc}")
            result = {
                "primary_domain": "unknown", "secondary_domains": [], "severity": "unknown", "health_status": "unknown",
                "urgency_reason": "Structured ambiguity analysis unavailable", "findings": [], "affected_components": [],
                "probable_dependencies": [], "blast_radius": "unknown", "hypotheses": [],
                "missing_evidence": ["specialist triage result"], "evidence_gaps": [], "next_best_evidence": [],
                "specialist_routes": [], "route_reasons": [], "rejected_routes": [],
                "immediate_checks": ["Collect live alerts, logs and metrics"], "escalation_target": "incident-commander",
                "risk_level": "low", "uncertainty_reason": "structured_analysis_failed", "confidence": 0.0,
            }

        model_primary = str(result.get("primary_domain", "unknown")).lower()
        if model_primary not in valid_routes and model_primary != "unknown":
            model_primary = "unknown"
        decision_primary = str(decision.get("primary_domain") or "unknown").lower()
        band = str(decision.get("routing_confidence_band") or "low").lower()
        focused_routes = [
            str(route).lower() for route in decision.get("specialist_routes", [])
            if str(route).lower() in valid_routes
        ][: settings.AGENT_MAX_PARALLELISM]

        # Deterministic routing owns high/medium confidence decisions. The LLM may
        # resolve a low-confidence ambiguity only inside the bounded candidate set.
        if decision_primary in valid_routes and band in {"high", "medium"}:
            primary = decision_primary
        elif model_primary in valid_routes and (not focused_routes or model_primary in focused_routes):
            primary = model_primary
        elif decision_primary in valid_routes:
            primary = decision_primary
        else:
            primary = "unknown"

        deterministic_secondary = [
            str(domain).lower() for domain in decision.get("secondary_domains", [])
            if str(domain).lower() in valid_routes and str(domain).lower() != primary
        ]
        model_secondary = [
            domain for domain in self.normalize_list(result.get("secondary_domains"), 6)
            if domain in valid_routes and domain != primary
        ]
        secondary: List[str] = []
        for domain in deterministic_secondary + model_secondary:
            if domain not in secondary and (band == "low" or domain in focused_routes or len(secondary) < 2):
                secondary.append(domain)

        legacy_asset_routes = [route for route in self._legacy_asset_routes(asset) if route in valid_routes]
        model_routes = [
            route for route in self.normalize_list(result.get("specialist_routes"), settings.AGENT_MAX_PARALLELISM)
            if route in valid_routes
        ]
        # handoff_agents remains backward compatible for external clients. Runtime
        # coordinator consumes analysis_details.specialist_routes for adaptive fan-out.
        handoff_routes: List[str] = []
        for route in legacy_asset_routes + focused_routes + model_routes + ([primary] if primary in valid_routes else []) + secondary:
            if route in valid_routes and route not in handoff_routes:
                handoff_routes.append(route)
            if len(handoff_routes) >= settings.AGENT_MAX_PARALLELISM:
                break

        missing = self.normalize_list(result.get("missing_evidence"), 8)
        for gap in decision.get("evidence_gap_matrix", []):
            if not isinstance(gap, dict):
                continue
            domain = str(gap.get("domain") or "triage")
            for item in gap.get("missing") or []:
                text = f"{domain}: {item}"
                if text not in missing:
                    missing.append(text)
                if len(missing) >= 12:
                    break
        if len(evidence) < settings.AGENT_MIN_EVIDENCE_ITEMS:
            missing = sorted(set(missing + ["live operational evidence"]))
        if decision.get("unknown_asset"):
            missing = sorted(set(missing + ["live asset identity metadata"] ))
        if decision.get("stale_evidence_count"):
            missing = sorted(set(missing + ["fresh evidence replacing stale observations"]))
        topology_conflicts = decision.get("topology_conflicts") or []
        if topology_conflicts:
            missing = sorted(set(missing + ["resolve live-vs-knowledge topology conflict"]))

        hypotheses = []
        conflict_count = len(topology_conflicts)
        for item in result.get("hypotheses", [])[: settings.AGENT_MAX_HYPOTHESES]:
            if isinstance(item, dict) and item.get("hypothesis"):
                conflicts = [str(x) for x in item.get("conflicting_evidence_ids", []) if str(x) in evidence_ids]
                conflict_count += len(conflicts)
                hypotheses.append(OperationalHypothesis(
                    hypothesis=str(item["hypothesis"]),
                    probability=self.safe_confidence(item.get("probability", 0), len(evidence), missing, len(conflicts)),
                    evidence_ids=[str(x) for x in item.get("evidence_ids", []) if str(x) in evidence_ids],
                    conflicting_evidence_ids=conflicts,
                    falsification_checks=self.normalize_list(item.get("falsification_checks"), 5),
                    impacted_components=self.normalize_list(item.get("impacted_components"), 6),
                    recommended_next_evidence=self.normalize_list(item.get("recommended_next_evidence"), 6),
                ))
        if not hypotheses and decision.get("causal_matches") and evidence_ids:
            for match in decision.get("causal_matches", [])[: settings.AGENT_MAX_HYPOTHESES]:
                next_checks = [
                    str(item.get("evidence")) for item in decision.get("next_best_evidence", [])
                    if isinstance(item, dict) and item.get("evidence")
                ][:4]
                hypotheses.append(OperationalHypothesis(
                    hypothesis=f"Probable causal path: {match.get('reason')}",
                    probability=max(0.0, min(1.0, float(decision.get("routing_confidence", 0) or 0))),
                    evidence_ids=evidence_ids[:8],
                    conflicting_evidence_ids=[],
                    falsification_checks=next_checks or ["Collect independent evidence from the proposed causal layer"],
                    impacted_components=[],
                    recommended_next_evidence=next_checks,
                ))

        model_confidence = result.get("confidence", 0)
        deterministic_confidence = float(decision.get("routing_confidence", 0) or 0)
        if band == "high":
            raw_confidence = max(deterministic_confidence, float(model_confidence or 0))
        elif band == "medium":
            raw_confidence = (deterministic_confidence + float(model_confidence or 0)) / 2
        else:
            raw_confidence = min(max(deterministic_confidence, float(model_confidence or 0)), settings.AGENT_LOW_CONFIDENCE_THRESHOLD)
        confidence = self.safe_confidence(raw_confidence, len(evidence), missing, conflict_count)

        actions = self.normalize_list(result.get("immediate_checks"), settings.AGENT_MAX_RECOMMENDATIONS)
        if not actions:
            actions = [
                f"Collect {item.get('evidence')} for {item.get('domain')}"
                for item in decision.get("next_best_evidence", [])
                if isinstance(item, dict) and item.get("evidence")
            ][: settings.AGENT_MAX_RECOMMENDATIONS]
        severity = str(decision.get("severity") or result.get("severity") or "unknown").lower()
        urgency_reason = str(decision.get("urgency_reason") or result.get("urgency_reason") or "not established")
        findings = self.normalize_list(result.get("findings"), 8)
        if decision.get("alert_storm_not_incident_storm"):
            findings.append("Correlated duplicate signals are treated as an alert storm/correlation group, not automatically as independent incidents")
        if topology_conflicts:
            findings.append("Topology conflict is explicit and requires live resolution before high-confidence routing")

        blast_radius = str(decision.get("blast_radius") or "unknown")
        if blast_radius == "unknown":
            blast_radius = str(result.get("blast_radius", "unknown"))
        statement = f"Incident triaged to {primary}; affected_layer={decision.get('affected_layer','unknown')}; severity={severity}; reason={urgency_reason}"
        return AgentOutput(
            agent_name=self.name,
            finding_type=f"triage_{primary}",
            statement=statement[:600],
            severity=severity,
            health_status=str(result.get("health_status", "unknown")).lower(),
            confidence=confidence,
            evidence_ids=evidence_ids,
            evidence_count=len(evidence),
            evidence_coverage=float(decision.get("primary_domain_coverage", self.evidence_coverage(len(evidence), missing)) or 0),
            findings=findings,
            recommendations=actions,
            recommended_actions=self.analysis_only_actions(actions),
            hypotheses=hypotheses,
            missing_evidence=missing,
            handoff_agents=handoff_routes,
            probable_dependencies=self.normalize_list(result.get("probable_dependencies"), 8),
            affected_components=self.normalize_list(result.get("affected_components"), 8),
            blast_radius=blast_radius,
            escalation_target=str(result.get("escalation_target") or "incident-commander"),
            risk_level=str(result.get("risk_level", "low")).lower(),
            uncertainty_reason=str(result.get("uncertainty_reason") or ("missing_evidence" if missing else "")) or None,
            requires_human_review=self.human_review_required(confidence, missing, severe=severity == "critical"),
            analysis_details={
                "primary_domain": primary,
                "secondary_domains": secondary,
                "affected_layer": decision.get("affected_layer"),
                "probable_causal_layer": decision.get("probable_causal_layer"),
                "urgency_reason": urgency_reason,
                "asset_context": asset,
                "asset_routing": legacy_asset_routes,
                "specialist_routes": focused_routes,
                "routing_confidence": decision.get("routing_confidence"),
                "routing_confidence_band": band,
                "route_reasons": decision.get("route_reasons", []),
                "rejected_routes": decision.get("rejected_routes", []),
                "evidence_gaps": decision.get("evidence_gap_matrix", []),
                "next_best_evidence": decision.get("next_best_evidence", []),
                "domain_evidence_coverage": decision.get("domain_evidence_coverage", {}),
                "correlation_groups": decision.get("correlation_groups", []),
                "alert_storm_groups": decision.get("alert_storm_groups", []),
                "alert_storm_not_incident_storm": decision.get("alert_storm_not_incident_storm", False),
                "timeline": decision.get("timeline", {}),
                "stale_evidence_ids": decision.get("stale_evidence_ids", []),
                "stale_evidence_count": decision.get("stale_evidence_count", 0),
                "topology_conflicts": topology_conflicts,
                "unknown_asset": decision.get("unknown_asset", False),
                "severity_details": decision.get("severity_details", {}),
                "causal_matches": decision.get("causal_matches", []),
                "deterministic_analysis": deterministic,
                "triage_decision_support": decision,
                "evidence_type_counts": type_counts,
                "evidence_source_counts": source_counts,
                "knowledge_context_count": len(auxiliary["knowledge_rag"]),
                "memory_context_count": len(auxiliary["operational_memory"]),
                "prior_incident_policy": "pattern_suggestion_only_not_current_incident_proof",
                "knowledge_assisted_asset": bool(asset.get("knowledge_assisted")),
                "asset_requires_live_verification": bool(asset.get("requires_live_verification")),
                "topology_conflict_count": len(topology_conflicts),
                "conflicting_evidence_count": conflict_count,
                "execution_boundary": "analysis_only",
            },
            model_metadata=self._last_model_metadata,
        )
