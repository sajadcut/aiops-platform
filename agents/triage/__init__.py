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
        type_counts = {}
        source_counts = {}
        for item in evidence:
            kind = str(item.get("type", "unknown")).lower()
            source = str(item.get("source", "unknown")).lower()
            type_counts[kind] = type_counts.get(kind, 0) + 1
            source_counts[source] = source_counts.get(source, 0) + 1

        prompt = f"""You are the incident commander triage agent for an AIOps platform. Use only supplied evidence. Your job is classification and routing, not remediation.
Classify primary_domain as one of application,infrastructure,kubernetes,security,vm,unknown. Also return secondary_domains when evidence spans layers.
Return JSON keys: primary_domain, secondary_domains, severity, health_status, urgency_reason, affected_components, blast_radius, hypotheses, missing_evidence, specialist_routes, immediate_checks, confidence.
Hypotheses entries: hypothesis, probability, evidence_ids, falsification_checks.
Never invent a specific VM, deployment, compromise, outage or metric. immediate_checks must be read-only evidence collection.
Incident={input_data.incident_id}\nService={input_data.service_name}\nSummary={input_data.evidence_summary}\nEvidence={json.dumps(evidence, default=str)}\nContextSummary={json.dumps(input_data.context.get('summary', {}), default=str)}"""
        try:
            result = json.loads((await self.llm.generate(prompt, temperature=settings.AGENT_LLM_TEMPERATURE)).content)
        except Exception as exc:
            logger.error(f"TriageAgent analysis failed: {exc}")
            result = {
                "primary_domain": "unknown",
                "secondary_domains": [],
                "severity": "unknown",
                "health_status": "unknown",
                "urgency_reason": "Structured triage unavailable",
                "affected_components": [],
                "blast_radius": "unknown",
                "hypotheses": [],
                "missing_evidence": ["specialist triage result"],
                "specialist_routes": ["application", "infrastructure"],
                "immediate_checks": ["Collect live alerts, logs and metrics"],
                "confidence": 0.0,
            }

        primary = str(result.get("primary_domain", "unknown")).lower()
        valid_routes = {"application", "infrastructure", "kubernetes", "security", "vm"}
        routes = [route for route in self.normalize_list(result.get("specialist_routes"), 5) if route in valid_routes]
        if primary in valid_routes and primary not in routes:
            routes.insert(0, primary)
        confidence = self.safe_confidence(result.get("confidence"), len(evidence))
        missing = self.normalize_list(result.get("missing_evidence"), 8)
        if len(evidence) < settings.AGENT_MIN_EVIDENCE_ITEMS:
            missing = sorted(set(missing + ["live operational evidence"]))
        actions = self.normalize_list(result.get("immediate_checks"), settings.AGENT_MAX_RECOMMENDATIONS)
        hypotheses = []
        for item in result.get("hypotheses", [])[: settings.AGENT_MAX_HYPOTHESES]:
            if isinstance(item, dict) and item.get("hypothesis"):
                hypotheses.append(OperationalHypothesis(
                    hypothesis=str(item["hypothesis"]),
                    probability=self.safe_confidence(item.get("probability", 0), len(evidence)),
                    evidence_ids=[str(x) for x in item.get("evidence_ids", []) if str(x) in evidence_ids],
                    falsification_checks=self.normalize_list(item.get("falsification_checks"), 4),
                ))
        severity = str(result.get("severity", "unknown")).lower()
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
            recommendations=actions,
            recommended_actions=self.analysis_only_actions(actions),
            hypotheses=hypotheses,
            missing_evidence=missing,
            handoff_agents=routes,
            affected_components=self.normalize_list(result.get("affected_components"), 8),
            blast_radius=str(result.get("blast_radius", "unknown")),
            requires_human_review=self.human_review_required(confidence, missing, severe=severity == "critical"),
            analysis_details={
                "primary_domain": primary,
                "secondary_domains": self.normalize_list(result.get("secondary_domains"), 5),
                "urgency_reason": result.get("urgency_reason"),
                "evidence_type_counts": type_counts,
                "evidence_source_counts": source_counts,
            },
        )
