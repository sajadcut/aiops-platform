import json
from typing import List, Optional

from agents.shared.base import AgentInput, AgentOutput, BaseAgent, OperationalHypothesis
from domain.contracts.config import settings
from domain.contracts.logging import logger
from integrations.llm.base import LLMAdapter


class ApplicationAgent(BaseAgent):
    def __init__(self, llm_adapter: Optional[LLMAdapter] = None):
        super().__init__(llm_adapter)

    @property
    def name(self) -> str:
        return "application"

    @property
    def description(self) -> str:
        return "Application reliability analysis: errors, dependencies, releases, latency, endpoints and configuration"

    @property
    def allowed_tools(self) -> List[str]:
        return ["elasticsearch_logs", "prometheus_query", "knowledge_search"]

    async def analyze(self, input_data: AgentInput) -> AgentOutput:
        logger.info(f"ApplicationAgent analyzing: {input_data.incident_id}")
        evidence = self.evidence_items(input_data)
        evidence_ids = self.evidence_ids(input_data)
        auxiliary = self.auxiliary_context(input_data)
        logs = [item for item in evidence if str(item.get("type", "")).lower() == "log"]
        metrics = [item for item in evidence if str(item.get("type", "")).lower() == "metric"]
        missing = self.missing_evidence_for(input_data, ["log", "metric"])
        prompt = f"""You are a senior SRE application analyst. LIVE EVIDENCE is authoritative. Auxiliary Knowledge RAG and Operational Memory may suggest checks/patterns but must never be cited as proof of current state. Never invent deployments, dependencies, versions, configuration changes, exceptions or executed actions.
Analyze: 4xx/5xx patterns, latency/error-rate changes, exception clustering, endpoint-level impact, dependency health, release/deployment correlation, config drift signals and saturation visible at the application boundary.
Return JSON keys: severity, health_status, findings, error_patterns, http_status_patterns, latency_signals, exception_clusters, endpoint_impacts, deployment_correlation, config_drift_signals, dependency_signals, probable_dependencies, affected_components, blast_radius, hypotheses, missing_evidence, handoff_agents, immediate_checks, escalation_target, risk_level, uncertainty_reason, confidence.
Each hypothesis: hypothesis, probability, evidence_ids, conflicting_evidence_ids, falsification_checks, impacted_components, recommended_next_evidence. Only LIVE EVIDENCE IDs may appear in evidence fields. Immediate checks are read-only.
Incident={input_data.incident_id}\nService={input_data.service_name}\nSummary={input_data.evidence_summary}\nLIVE_EVIDENCE={json.dumps(evidence, default=str)}\nAUXILIARY_CONTEXT={json.dumps(auxiliary, default=str)}\nContextSummary={json.dumps(input_data.context.get('summary', {}), default=str)}"""
        try:
            result = await self.generate_structured(prompt)
        except Exception as exc:
            logger.error(f"ApplicationAgent analysis failed: {exc}")
            result = {"severity":"unknown","health_status":"unknown","findings":[],"error_patterns":[],"affected_components":[],"blast_radius":"unknown","hypotheses":[],"handoff_agents":["triage"],"immediate_checks":["Collect application logs and service metrics"],"uncertainty_reason":"structured_analysis_failed","confidence":0.0}
            missing = sorted(set(missing + ["successful structured application analysis"]))

        all_missing = sorted(set(missing + self.normalize_list(result.get("missing_evidence"), 8)))
        hypotheses = []
        conflict_count = 0
        for item in result.get("hypotheses", [])[: settings.AGENT_MAX_HYPOTHESES]:
            if isinstance(item, dict) and item.get("hypothesis"):
                conflicts = [str(x) for x in item.get("conflicting_evidence_ids", []) if str(x) in evidence_ids]
                conflict_count += len(conflicts)
                hypotheses.append(OperationalHypothesis(
                    hypothesis=str(item["hypothesis"]),
                    probability=self.safe_confidence(item.get("probability", 0), len(evidence), all_missing, len(conflicts)),
                    evidence_ids=[str(x) for x in item.get("evidence_ids", []) if str(x) in evidence_ids],
                    conflicting_evidence_ids=conflicts,
                    falsification_checks=self.normalize_list(item.get("falsification_checks"), 5),
                    impacted_components=self.normalize_list(item.get("impacted_components"), 6),
                    recommended_next_evidence=self.normalize_list(item.get("recommended_next_evidence"), 6),
                ))
        confidence = self.safe_confidence(result.get("confidence"), len(evidence), all_missing, conflict_count)
        actions = self.normalize_list(result.get("immediate_checks"), settings.AGENT_MAX_RECOMMENDATIONS)
        patterns = self.normalize_list(result.get("error_patterns"), 6)
        findings = self.normalize_list(result.get("findings"), 10) or patterns
        statement = "Application evidence indicates " + ("; ".join(findings) if findings else "no confirmed application fault pattern yet")
        return AgentOutput(
            agent_name=self.name,
            finding_type="application_analysis",
            statement=statement[:600],
            severity=str(result.get("severity", "unknown")).lower(),
            health_status=str(result.get("health_status", "unknown")).lower(),
            confidence=confidence,
            evidence_ids=evidence_ids,
            evidence_count=len(evidence),
            evidence_coverage=self.evidence_coverage(len(evidence), all_missing),
            findings=findings,
            recommendations=actions,
            recommended_actions=self.analysis_only_actions(actions),
            hypotheses=hypotheses,
            missing_evidence=all_missing,
            handoff_agents=self.normalize_list(result.get("handoff_agents"), 6),
            probable_dependencies=self.normalize_list(result.get("probable_dependencies") or result.get("dependency_signals"), 8),
            affected_components=self.normalize_list(result.get("affected_components"), 8),
            blast_radius=str(result.get("blast_radius", "unknown")),
            escalation_target=str(result.get("escalation_target") or "application-sre"),
            risk_level=str(result.get("risk_level", "low")).lower(),
            uncertainty_reason=str(result.get("uncertainty_reason") or ("missing_evidence" if all_missing else "")) or None,
            requires_human_review=self.human_review_required(confidence, all_missing),
            analysis_details={
                "error_patterns": patterns,
                "http_status_patterns": result.get("http_status_patterns", []),
                "latency_signals": result.get("latency_signals", []),
                "exception_clusters": result.get("exception_clusters", []),
                "endpoint_impacts": result.get("endpoint_impacts", []),
                "deployment_correlation": result.get("deployment_correlation"),
                "config_drift_signals": result.get("config_drift_signals", []),
                "dependency_signals": result.get("dependency_signals", []),
                "log_evidence_count": len(logs),
                "metric_evidence_count": len(metrics),
                "knowledge_context_count": len(auxiliary["knowledge_rag"]),
                "memory_context_count": len(auxiliary["operational_memory"]),
                "conflicting_evidence_count": conflict_count,
            },
            model_metadata=self._last_model_metadata,
        )
