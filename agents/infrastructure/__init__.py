import json
from typing import List, Optional

from agents.shared.base import AgentInput, AgentOutput, BaseAgent, OperationalHypothesis
from agents.shared.intelligence import build_deterministic_analysis, prompt_evidence_projection, sanitize_prompt_value
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
        prompt_evidence = prompt_evidence_projection(evidence, settings.AGENT_MAX_EVIDENCE_ITEMS)
        deterministic = build_deterministic_analysis("infrastructure", evidence, ["metric"], input_data.service_name)
        evidence_ids = self.evidence_ids(input_data)
        auxiliary = self.auxiliary_context(input_data)
        metrics = [item for item in evidence if str(item.get("type", "")).lower() == "metric"]
        alerts = [item for item in evidence if str(item.get("type", "")).lower() == "alert"]
        missing = self.missing_evidence_for(input_data, ["metric"])
        prompt = f"""You are a senior infrastructure/SRE reliability investigator. LIVE EVIDENCE is authoritative. Knowledge RAG and Operational Memory are auxiliary only and cannot prove current host state. Do not infer saturation, capacity exhaustion, node failure or network faults without live evidence.
Use the USE model: utilization, saturation and errors. Distinguish high utilization that remains healthy from real saturation. Inspect any available CPU utilization/load versus cores/run queue/iowait/steal/throttling/softirq; memory available/working set/cache/swap/page faults/reclaim/OOM/PSI; disk utilization/await/queue depth/throughput/IOPS/device errors/capacity/inodes; kernel/system PSI, file descriptors, process count, conntrack, hung tasks and hardware telemetry; capacity baseline, percentile, growth and sudden contention. Separate application-driven host pressure, storage bottlenecks expressed as iowait, network interrupt pressure, VM steal and resource leaks.
DETERMINISTIC_ANALYSIS contains bounded timeline, metric baseline deltas, evidence gaps and direct signals. It is observation-only. Every finding should state or imply when the anomaly appeared relative to the incident when timestamps exist. Prefer causal alternatives and falsification over threshold-only conclusions.
Return JSON keys: severity, health_status, findings, saturation_signals, capacity_risks, network_signals, node_signals, probable_dependencies, affected_components, blast_radius, hypotheses, missing_evidence, handoff_agents, immediate_checks, escalation_target, risk_level, uncertainty_reason, confidence.
Hypotheses entries: hypothesis, probability, evidence_ids, conflicting_evidence_ids, falsification_checks, impacted_components, recommended_next_evidence. Only live evidence IDs may be cited. Immediate checks are read-only.
Incident={input_data.incident_id}\nService={input_data.service_name}\nSummary={input_data.evidence_summary}\nDETERMINISTIC_ANALYSIS={json.dumps(deterministic, default=str)}\nLIVE_EVIDENCE={json.dumps(prompt_evidence, default=str)}\nAUXILIARY_CONTEXT={json.dumps(sanitize_prompt_value(auxiliary), default=str)}\nContextSummary={json.dumps(sanitize_prompt_value(input_data.context.get('summary', {})), default=str)}"""
        try:
            result = await self.generate_structured(prompt)
        except Exception as exc:
            logger.error(f"InfrastructureAgent analysis failed: {exc}")
            result = {"severity":"unknown","health_status":"unknown","findings":[],"saturation_signals":[],"capacity_risks":[],"network_signals":[],"node_signals":[],"affected_components":[],"blast_radius":"unknown","hypotheses":[],"handoff_agents":["triage"],"immediate_checks":["Collect host and service metrics"],"uncertainty_reason":"structured_analysis_failed","confidence":0.0}
            missing = sorted(set(missing + ["successful structured infrastructure analysis"]))

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
        saturation = self.normalize_list(result.get("saturation_signals"), 6)
        findings = self.normalize_list(result.get("findings"), 10) or saturation
        handoffs = self.normalize_list(result.get("handoff_agents"), 6)
        for hint in deterministic.get("suggested_handoffs", []):
            target = str(hint.get("agent", "")) if isinstance(hint, dict) else ""
            if target and target != self.name and target not in handoffs and len(handoffs) < 6:
                handoffs.append(target)
        statement = "Infrastructure evidence indicates " + ("; ".join(findings) if findings else "no confirmed saturation or host fault yet")
        return AgentOutput(
            agent_name=self.name,
            finding_type="infrastructure_analysis",
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
            handoff_agents=handoffs,
            probable_dependencies=self.normalize_list(result.get("probable_dependencies"), 8),
            affected_components=self.normalize_list(result.get("affected_components"), 8),
            blast_radius=str(result.get("blast_radius", "unknown")),
            escalation_target=str(result.get("escalation_target") or "infrastructure-sre"),
            risk_level=str(result.get("risk_level", "low")).lower(),
            uncertainty_reason=str(result.get("uncertainty_reason") or ("missing_evidence" if all_missing else "")) or None,
            requires_human_review=self.human_review_required(confidence, all_missing),
            analysis_details={
                "saturation_signals": saturation,
                "capacity_risks": result.get("capacity_risks", []),
                "network_signals": result.get("network_signals", []),
                "node_signals": result.get("node_signals", []),
                "infrastructure_health_matrix": {
                    "cpu_memory_disk_kernel_checks": deterministic.get("playbook_checks", []),
                    "metric_series": deterministic.get("metric_features", {}).get("series", {}),
                    "baseline_deltas": deterministic.get("metric_features", {}).get("largest_baseline_deltas", []),
                },
                "deterministic_analysis": deterministic,
                "next_best_evidence": deterministic.get("next_best_evidence", []),
                "metric_evidence_count": len(metrics),
                "alert_evidence_count": len(alerts),
                "knowledge_context_count": len(auxiliary["knowledge_rag"]),
                "memory_context_count": len(auxiliary["operational_memory"]),
                "conflicting_evidence_count": conflict_count,
            },
            model_metadata=self._last_model_metadata,
        )
