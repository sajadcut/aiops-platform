import json
from typing import List, Optional

from agents.shared.base import AgentInput, AgentOutput, BaseAgent, OperationalHypothesis
from domain.contracts.config import settings
from domain.contracts.logging import logger
from integrations.llm.base import LLMAdapter


class KubernetesAgent(BaseAgent):
    def __init__(self, llm_adapter: Optional[LLMAdapter] = None):
        super().__init__(llm_adapter)

    @property
    def name(self) -> str:
        return "kubernetes"

    @property
    def description(self) -> str:
        return "Kubernetes diagnostics: workload health, rollout, scheduling, networking, resources and events"

    @property
    def allowed_tools(self) -> List[str]:
        return ["kubectl_get", "kubectl_describe", "kubectl_logs", "prometheus_query", "knowledge_search"]

    async def analyze(self, input_data: AgentInput) -> AgentOutput:
        logger.info(f"KubernetesAgent analyzing: {input_data.incident_id}")
        evidence = self.evidence_items(input_data)
        evidence_ids = self.evidence_ids(input_data)
        logs = [item for item in evidence if str(item.get("type", "")).lower() == "log"]
        metrics = [item for item in evidence if str(item.get("type", "")).lower() == "metric"]
        events = [item for item in evidence if str(item.get("type", "")).lower() in {"event", "alert"}]
        missing = self.missing_evidence_for(input_data, ["log", "metric"])
        prompt = f"""You are a Kubernetes SRE. Analyze only supplied evidence; do not claim pod states, rollout failures, OOMKills, scheduling failures or network faults unless evidenced.
Return JSON keys: severity, health_status, workload_signals, rollout_signals, scheduling_signals, network_signals, resource_signals, affected_components, blast_radius, hypotheses, missing_evidence, handoff_agents, immediate_checks, confidence.
Hypotheses entries: hypothesis, probability, evidence_ids, falsification_checks. immediate_checks must be read-only kubectl/metrics/log inspection.
Incident={input_data.incident_id}\nService={input_data.service_name}\nSummary={input_data.evidence_summary}\nEvidence={json.dumps(evidence, default=str)}\nContextSummary={json.dumps(input_data.context.get('summary', {}), default=str)}"""
        try:
            result = json.loads((await self.llm.generate(prompt, temperature=settings.AGENT_LLM_TEMPERATURE)).content)
        except Exception as exc:
            logger.error(f"KubernetesAgent analysis failed: {exc}")
            result = {"severity": "unknown", "health_status": "unknown", "workload_signals": [], "affected_components": [], "blast_radius": "unknown", "hypotheses": [], "handoff_agents": ["infrastructure"], "immediate_checks": ["Inspect workload status, events and recent logs"], "confidence": 0.0}
            missing = sorted(set(missing + ["successful structured kubernetes analysis"]))

        confidence = self.safe_confidence(result.get("confidence"), len(evidence))
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
        workload = self.normalize_list(result.get("workload_signals"), 6)
        statement = "Kubernetes evidence indicates " + ("; ".join(workload) if workload else "no confirmed workload failure yet")
        return AgentOutput(
            agent_name=self.name,
            finding_type="kubernetes_analysis",
            statement=statement[:600],
            severity=str(result.get("severity", "unknown")).lower(),
            health_status=str(result.get("health_status", "unknown")).lower(),
            confidence=confidence,
            evidence_ids=evidence_ids,
            evidence_count=len(evidence),
            recommendations=actions,
            recommended_actions=self.analysis_only_actions(actions, suggested_tool="kubectl_get"),
            hypotheses=hypotheses,
            missing_evidence=sorted(set(missing + self.normalize_list(result.get("missing_evidence"), 6))),
            handoff_agents=self.normalize_list(result.get("handoff_agents"), 4),
            affected_components=self.normalize_list(result.get("affected_components"), 8),
            blast_radius=str(result.get("blast_radius", "unknown")),
            requires_human_review=self.human_review_required(confidence, missing),
            analysis_details={
                "workload_signals": workload,
                "rollout_signals": result.get("rollout_signals", []),
                "scheduling_signals": result.get("scheduling_signals", []),
                "network_signals": result.get("network_signals", []),
                "resource_signals": result.get("resource_signals", []),
                "log_evidence_count": len(logs),
                "metric_evidence_count": len(metrics),
                "event_evidence_count": len(events),
            },
        )
