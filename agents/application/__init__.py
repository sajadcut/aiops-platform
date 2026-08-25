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
        return "Application reliability analysis: errors, dependencies, releases, latency and configuration"

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
        prompt = f"""You are a senior SRE application analyst. Use LIVE EVIDENCE as the source of truth. Auxiliary Knowledge RAG and Operational Memory may suggest checks/patterns but must never be cited as proof of current state. Never invent deployments, dependencies, versions, errors or actions already executed.
Return JSON with keys: severity, health_status, error_patterns, deployment_correlation, dependency_signals, affected_components, blast_radius, hypotheses, missing_evidence, handoff_agents, immediate_checks, confidence.
Each hypothesis must contain hypothesis, probability, evidence_ids, conflicting_evidence_ids, falsification_checks. Only IDs from LIVE EVIDENCE may appear in evidence fields.
Immediate checks must be read-only observations, never mutation.
Incident={input_data.incident_id}\nService={input_data.service_name}\nSummary={input_data.evidence_summary}\nLIVE_EVIDENCE={json.dumps(evidence, default=str)}\nAUXILIARY_CONTEXT={json.dumps(auxiliary, default=str)}\nContextSummary={json.dumps(input_data.context.get('summary', {}), default=str)}"""
        try:
            result = json.loads((await self.llm.generate(prompt, temperature=settings.AGENT_LLM_TEMPERATURE)).content)
        except Exception as exc:
            logger.error(f"ApplicationAgent analysis failed: {exc}")
            result = {"severity": "unknown", "health_status": "unknown", "error_patterns": [], "affected_components": [], "blast_radius": "unknown", "hypotheses": [], "handoff_agents": ["triage"], "immediate_checks": ["Collect application logs and service metrics"], "confidence": 0.0}
            missing = sorted(set(missing + ["successful structured application analysis"]))

        confidence = self.safe_confidence(result.get("confidence"), len(evidence))
        actions = self.normalize_list(result.get("immediate_checks"), settings.AGENT_MAX_RECOMMENDATIONS)
        hypotheses = []
        for item in result.get("hypotheses", [])[: settings.AGENT_MAX_HYPOTHESES]:
            if isinstance(item, dict) and item.get("hypothesis"):
                hypotheses.append(OperationalHypothesis(
                    hypothesis=str(item["hypothesis"]),
                    probability=self.safe_confidence(item.get("probability", 0), len(evidence)),
                    evidence_ids=[str(x) for x in item.get("evidence_ids", []) if str(x) in evidence_ids],
                    conflicting_evidence_ids=[str(x) for x in item.get("conflicting_evidence_ids", []) if str(x) in evidence_ids],
                    falsification_checks=self.normalize_list(item.get("falsification_checks"), 4),
                ))
        patterns = self.normalize_list(result.get("error_patterns"), 5)
        all_missing = sorted(set(missing + self.normalize_list(result.get("missing_evidence"), 6)))
        statement = "Application evidence indicates " + ("; ".join(patterns) if patterns else "no confirmed application fault pattern yet")
        return AgentOutput(
            agent_name=self.name,
            finding_type="application_analysis",
            statement=statement[:600],
            severity=str(result.get("severity", "unknown")).lower(),
            health_status=str(result.get("health_status", "unknown")).lower(),
            confidence=confidence,
            evidence_ids=evidence_ids,
            evidence_count=len(evidence),
            recommendations=actions,
            recommended_actions=self.analysis_only_actions(actions),
            hypotheses=hypotheses,
            missing_evidence=all_missing,
            handoff_agents=self.normalize_list(result.get("handoff_agents"), 4),
            affected_components=self.normalize_list(result.get("affected_components"), 8),
            blast_radius=str(result.get("blast_radius", "unknown")),
            requires_human_review=self.human_review_required(confidence, all_missing),
            analysis_details={
                "error_patterns": patterns,
                "deployment_correlation": result.get("deployment_correlation"),
                "dependency_signals": result.get("dependency_signals", []),
                "log_evidence_count": len(logs),
                "metric_evidence_count": len(metrics),
                "knowledge_context_count": len(auxiliary["knowledge_rag"]),
                "memory_context_count": len(auxiliary["operational_memory"]),
            },
        )
