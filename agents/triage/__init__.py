import json
from typing import List, Optional

from agents.shared.base import AgentInput, AgentOutput, BaseAgent, OperationalHypothesis
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
        return "Incident triage: classify domain, assess urgency, determine evidence gaps and route specialist analysis"

    @property
    def allowed_tools(self) -> List[str]:
        return ["zabbix_read", "elasticsearch_logs", "prometheus_query", "kubectl_get", "vm_telemetry", "knowledge_search"]

    async def analyze(self, input_data: AgentInput) -> AgentOutput:
        logger.info(f"TriageAgent analyzing: {input_data.incident_id}")
        evidence = self.evidence_items(input_data)
        evidence_ids = self.evidence_ids(input_data)
        auxiliary = self.auxiliary_context(input_data)
        live = input_data.context.get("live_evidence", {}) if input_data.context else {}
        asset = input_data.context.get("asset_context") or (live.get("asset_context", {}) if isinstance(live, dict) else {}) or {}
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
        prompt = f"""You are the incident triage coordinator for a production AIOps platform. LIVE EVIDENCE is authoritative. RAG/Memory are auxiliary only. ASSET_CONTEXT is deterministic metadata from Zabbix inventory/tags, Prometheus labels, Elastic ECS fields and Kubernetes/VM telemetry; use it for target/platform identity and do not contradict it without explicit live evidence.
Classify primary_domain from {domains}. Return secondary_domains for cross-layer incidents.
Return JSON keys: primary_domain, secondary_domains, severity, health_status, urgency_reason, findings, affected_components, probable_dependencies, blast_radius, hypotheses, missing_evidence, specialist_routes, immediate_checks, escalation_target, risk_level, uncertainty_reason, confidence.
Hypotheses: hypothesis, probability, evidence_ids, conflicting_evidence_ids, falsification_checks, impacted_components, recommended_next_evidence. Only live evidence IDs may be cited.
Never invent a VM, OS, Kubernetes workload, deployment, compromise, outage, DB failure, packet loss, queue backlog, recovery failure or metric. immediate_checks are read-only evidence collection.
Incident={input_data.incident_id}\nService={input_data.service_name}\nSummary={input_data.evidence_summary}\nASSET_CONTEXT={json.dumps(asset, default=str)}\nLIVE_EVIDENCE={json.dumps(evidence, default=str)}\nAUXILIARY_CONTEXT={json.dumps(auxiliary, default=str)}\nContextSummary={json.dumps(input_data.context.get('summary', {}), default=str)}"""
        try:
            result = await self.generate_structured(prompt)
        except Exception as exc:
            logger.error(f"TriageAgent analysis failed: {exc}")
            result = {
                "primary_domain":"unknown","secondary_domains":[],"severity":"unknown","health_status":"unknown",
                "urgency_reason":"Structured triage unavailable","findings":[],"affected_components":[],
                "probable_dependencies":[],"blast_radius":"unknown","hypotheses":[],
                "missing_evidence":["specialist triage result"],"specialist_routes":[],
                "immediate_checks":["Collect live alerts, logs and metrics"],"escalation_target":"incident-commander",
                "risk_level":"low","uncertainty_reason":"structured_analysis_failed","confidence":0.0,
            }

        valid_routes = {str(name).lower() for name in settings.AGENT_ENABLED_AGENTS}
        primary = str(result.get("primary_domain", "unknown")).lower()
        if primary not in valid_routes and primary != "unknown":
            primary = "unknown"
        secondary = [domain for domain in self.normalize_list(result.get("secondary_domains"), 6) if domain in valid_routes and domain != primary]
        routes = [route for route in self.normalize_list(result.get("specialist_routes"), settings.AGENT_MAX_PARALLELISM) if route in valid_routes]

        # Deterministic asset routing has precedence over model guesses.
        asset_type = str(asset.get("asset_type") or "unknown").lower()
        platform = str(asset.get("platform") or "unknown").lower()
        deterministic_routes: List[str] = []
        if platform == "kubernetes" or "kubernetes" in asset_type:
            deterministic_routes = ["kubernetes", "infrastructure"]
            primary = "kubernetes"
        elif asset_type == "database":
            deterministic_routes = ["database", "infrastructure"]
            primary = "database"
        elif asset_type == "vm" or platform == "vm" or str(asset.get("os_family") or "unknown").lower() in {"linux", "windows"}:
            deterministic_routes = ["vm", "infrastructure"]
            if primary == "unknown":
                primary = "vm"
        for route in reversed(deterministic_routes):
            if route in valid_routes and route not in routes:
                routes.insert(0, route)
        if primary in valid_routes and primary not in routes:
            routes.insert(0, primary)
        for domain in secondary:
            if domain not in routes and len(routes) < settings.AGENT_MAX_PARALLELISM:
                routes.append(domain)
        routes = routes[: settings.AGENT_MAX_PARALLELISM]

        missing = self.normalize_list(result.get("missing_evidence"), 8)
        if len(evidence) < settings.AGENT_MIN_EVIDENCE_ITEMS:
            missing = sorted(set(missing + ["live operational evidence"]))
        if float(asset.get("confidence", 0) or 0) < 0.5:
            missing = sorted(set(missing + ["reliable asset identity metadata"]))

        hypotheses = []
        conflict_count = 0
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
        confidence = self.safe_confidence(result.get("confidence"), len(evidence), missing, conflict_count)
        actions = self.normalize_list(result.get("immediate_checks"), settings.AGENT_MAX_RECOMMENDATIONS)
        severity = str(result.get("severity", "unknown")).lower()
        findings = self.normalize_list(result.get("findings"), 8)
        statement = f"Incident triaged to {primary}; asset={asset_type}/{asset.get('os_family','unknown')}; severity={severity}; reason={str(result.get('urgency_reason', 'not established'))}"
        return AgentOutput(
            agent_name=self.name,
            finding_type=f"triage_{primary}",
            statement=statement[:600], severity=severity,
            health_status=str(result.get("health_status", "unknown")).lower(), confidence=confidence,
            evidence_ids=evidence_ids, evidence_count=len(evidence), evidence_coverage=self.evidence_coverage(len(evidence), missing),
            findings=findings, recommendations=actions, recommended_actions=self.analysis_only_actions(actions),
            hypotheses=hypotheses, missing_evidence=missing, handoff_agents=routes,
            probable_dependencies=self.normalize_list(result.get("probable_dependencies"), 8),
            affected_components=self.normalize_list(result.get("affected_components"), 8),
            blast_radius=str(result.get("blast_radius", "unknown")), escalation_target=str(result.get("escalation_target") or "incident-commander"),
            risk_level=str(result.get("risk_level", "low")).lower(),
            uncertainty_reason=str(result.get("uncertainty_reason") or ("missing_evidence" if missing else "")) or None,
            requires_human_review=self.human_review_required(confidence, missing, severe=severity == "critical"),
            analysis_details={
                "primary_domain": primary, "secondary_domains": secondary, "urgency_reason": result.get("urgency_reason"),
                "asset_context": asset, "asset_routing": deterministic_routes,
                "evidence_type_counts": type_counts, "evidence_source_counts": source_counts,
                "knowledge_context_count": len(auxiliary["knowledge_rag"]), "memory_context_count": len(auxiliary["operational_memory"]),
                "conflicting_evidence_count": conflict_count,
            },
            model_metadata=self._last_model_metadata,
        )
