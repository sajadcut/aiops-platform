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
        return ["zabbix_read", "elasticsearch_logs", "prometheus_query", "vm_telemetry", "knowledge_search"]

    async def analyze(self, input_data: AgentInput) -> AgentOutput:
        logger.info(f"TriageAgent analyzing: {input_data.incident_id}")
        evidence = self.evidence_items(input_data)
        evidence_ids = self.evidence_ids(input_data)
        auxiliary = self.auxiliary_context(input_data)
        type_counts = {}
        source_counts = {}
        for item in evidence:
            kind = str(item.get("type", "unknown")).lower()
            source = str(item.get("source", "unknown")).lower()
            type_counts[kind] = type_counts.get(kind, 0) + 1
            source_counts[source] = source_counts.get(source, 0) + 1

        domains = ["application","infrastructure","kubernetes","security","vm","database","network","storage","identity","change","unknown"]
        prompt = f"""You are the incident triage coordinator for a production AIOps platform. LIVE EVIDENCE is authoritative. RAG/Memory are auxiliary only. Your job is classification/routing, never remediation.
Classify primary_domain from {domains}. Return secondary_domains for cross-layer incidents.
Return JSON keys: primary_domain, secondary_domains, severity, health_status, urgency_reason, findings, affected_components, probable_dependencies, blast_radius, hypotheses, missing_evidence, specialist_routes, immediate_checks, escalation_target, risk_level, uncertainty_reason, confidence.
Hypotheses: hypothesis, probability, evidence_ids, conflicting_evidence_ids, falsification_checks, impacted_components, recommended_next_evidence. Only live evidence IDs may be cited.
Never invent a VM, deployment, compromise, outage, DB failure, packet loss or metric. immediate_checks are read-only evidence collection.
Incident={input_data.incident_id}\nService={input_data.service_name}\nSummary={input_data.evidence_summary}\nLIVE_EVIDENCE={json.dumps(evidence, default=str)}\nAUXILIARY_CONTEXT={json.dumps(auxiliary, default=str)}\nContextSummary={json.dumps(input_data.context.get('summary', {}), default=str)}"""
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

        valid_routes = set(settings.AGENT_ENABLED_AGENTS)
        primary = str(result.get("primary_domain", "unknown")).lower()
        if primary not in valid_routes and primary != "unknown":
            primary = "unknown"
        routes = [route for route in self.normalize_list(result.get("specialist_routes"), settings.AGENT_MAX_PARALLELISM) if route in valid_routes]
        if primary in valid_routes and primary not in routes:
            routes.insert(0, primary)
        missing = self.normalize_list(result.get("missing_evidence"), 8)
        if len(evidence) < settings.AGENT_MIN_EVIDENCE_ITEMS:
            missing = sorted(set(missing + ["live operational evidence"]))
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
        statement = f"Incident triaged to {primary}; severity={severity}; reason={str(result.get('urgency_reason', 'not established'))}"
        return AgentOutput(
            agent_name=self.name,
            finding_type=f"triage_{primary}",
            statement=statement[:600],
            severity=severity,
            health_status=str(result.get("health_status", "unknown")).lower(),
            confidence=confidence,
            evidence_ids=evidence_ids,
            evidence_count=len(evidence),
            evidence_coverage=self.evidence_coverage(len(evidence), missing),
            findings=findings,
            recommendations=actions,
            recommended_actions=self.analysis_only_actions(actions),
            hypotheses=hypotheses,
            missing_evidence=missing,
            handoff_agents=routes,
            probable_dependencies=self.normalize_list(result.get("probable_dependencies"), 8),
            affected_components=self.normalize_list(result.get("affected_components"), 8),
            blast_radius=str(result.get("blast_radius", "unknown")),
            escalation_target=str(result.get("escalation_target") or "incident-commander"),
            risk_level=str(result.get("risk_level", "low")).lower(),
            uncertainty_reason=str(result.get("uncertainty_reason") or ("missing_evidence" if missing else "")) or None,
            requires_human_review=self.human_review_required(confidence, missing, severe=severity == "critical"),
            analysis_details={
                "primary_domain": primary,
                "secondary_domains": [d for d in self.normalize_list(result.get("secondary_domains"), 6) if d in valid_routes],
                "urgency_reason": result.get("urgency_reason"),
                "evidence_type_counts": type_counts,
                "evidence_source_counts": source_counts,
                "knowledge_context_count": len(auxiliary["knowledge_rag"]),
                "memory_context_count": len(auxiliary["operational_memory"]),
                "conflicting_evidence_count": conflict_count,
            },
            model_metadata=self._last_model_metadata,
        )
