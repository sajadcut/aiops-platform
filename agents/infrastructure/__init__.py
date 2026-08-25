import json
from typing import List, Optional

from agents.shared.base import AgentInput, AgentOutput, BaseAgent, OperationalHypothesis
from domain.contracts.config import settings
from domain.contracts.logging import logger
from integrations.llm.base import LLMAdapter


class InfrastructureAgent(BaseAgent):
    def __init__(self, llm_adapter: Optional[LLMAdapter] = None):
        super().__init__(llm_adapter)

    @property
    def name(self) -> str:
        return "infrastructure"

    @property
    def description(self) -> str:
        return "Infrastructure diagnostics: saturation, capacity, network, hosts, storage and dependency health"

    @property
    def allowed_tools(self) -> List[str]:
        return ["prometheus_query", "zabbix_read", "vm_telemetry", "knowledge_search"]

    async def analyze(self, input_data: AgentInput) -> AgentOutput:
        logger.info(f"InfrastructureAgent analyzing: {input_data.incident_id}")
        evidence = self.evidence_items(input_data)
        evidence_ids = self.evidence_ids(input_data)
        auxiliary = self.auxiliary_context(input_data)
        metrics = [item for item in evidence if str(item.get("type", "")).lower() == "metric"]
        alerts = [item for item in evidence if str(item.get("type", "")).lower() == "alert"]
        missing = self.missing_evidence_for(input_data, ["metric"])
        prompt = f"""You are a senior infrastructure/SRE analyst. LIVE EVIDENCE is authoritative. Knowledge RAG and Operational Memory are auxiliary only and may suggest patterns or checks but cannot prove current host state. Do not infer saturation, capacity exhaustion, node failure or network faults without live evidence.
Return JSON keys: severity, health_status, saturation_signals, capacity_risks, network_signals, node_signals, affected_components, blast_radius, hypotheses, missing_evidence, handoff_agents, immediate_checks, confidence.
Hypotheses entries: hypothesis, probability, evidence_ids, conflicting_evidence_ids, falsification_checks. Only live evidence IDs may be cited. Immediate checks are read-only.
Incident={input_data.incident_id}\nService={input_data.service_name}\nSummary={input_data.evidence_summary}\nLIVE_EVIDENCE={json.dumps(evidence, default=str)}\nAUXILIARY_CONTEXT={json.dumps(auxiliary, default=str)}\nContextSummary={json.dumps(input_data.context.get('summary', {}), default=str)}"""
        try:
            result = json.loads((await self.llm.generate(prompt, temperature=settings.AGENT_LLM_TEMPERATURE)).content)
        except Exception as exc:
            logger.error(f"InfrastructureAgent analysis failed: {exc}")
            result = {"severity": "unknown", "health_status": "unknown", "saturation_signals": [], "capacity_risks": [], "network_signals": [], "node_signals": [], "affected_components": [], "blast_radius": "unknown", "hypotheses": [], "handoff_agents": ["triage"], "immediate_checks": ["Collect host and service metrics"], "confidence": 0.0}
            missing = sorted(set(missing + ["successful structured infrastructure analysis"]))

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
        saturation = self.normalize_list(result.get("saturation_signals"), 6)
        all_missing = sorted(set(missing + self.normalize_list(result.get("missing_evidence"), 6)))
        statement = "Infrastructure evidence indicates " + ("; ".join(saturation) if saturation else "no confirmed saturation or host fault yet")
        return AgentOutput(
            agent_name=self.name,
            finding_type="infrastructure_analysis",
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
                "saturation_signals": saturation,
                "capacity_risks": result.get("capacity_risks", []),
                "network_signals": result.get("network_signals", []),
                "node_signals": result.get("node_signals", []),
                "metric_evidence_count": len(metrics),
                "alert_evidence_count": len(alerts),
                "knowledge_context_count": len(auxiliary["knowledge_rag"]),
                "memory_context_count": len(auxiliary["operational_memory"]),
            },
        )
