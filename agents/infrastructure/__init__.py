import json
from typing import List, Optional

from agents.infrastructure.engine import build_infrastructure_analysis
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
        return "Infrastructure reliability investigation using deterministic USE, saturation, pressure, kernel and capacity evidence"

    @property
    def allowed_tools(self) -> List[str]:
        return ["prometheus_query", "zabbix_read", "vm_telemetry", "knowledge_search"]

    async def analyze(self, input_data: AgentInput) -> AgentOutput:
        logger.info(f"InfrastructureAgent analyzing: {input_data.incident_id}")
        evidence = self.evidence_items(input_data)
        prompt_evidence = prompt_evidence_projection(evidence, settings.AGENT_MAX_EVIDENCE_ITEMS)
        deterministic = build_deterministic_analysis("infrastructure", evidence, ["metric"], input_data.service_name)
        infrastructure_analysis = build_infrastructure_analysis(
            evidence,
            service_name=input_data.service_name,
            context=input_data.context,
        )
        evidence_ids = self.evidence_ids(input_data)
        auxiliary = self.auxiliary_context(input_data)
        metrics = [item for item in evidence if str(item.get("type", "")).lower() == "metric"]
        alerts = [item for item in evidence if str(item.get("type", "")).lower() == "alert"]
        telemetry = [item for item in evidence if str(item.get("type", "")).lower() == "telemetry"]
        missing = self.missing_evidence_for(input_data, ["metric"])

        prompt = f"""You are a senior infrastructure/SRE analyst and production Infrastructure Reliability Investigator. LIVE EVIDENCE is authoritative. Knowledge RAG and Operational Memory are auxiliary only and cannot prove current host state. Never infer saturation, capacity exhaustion, node failure, storage failure or network faults without live evidence.

INFRASTRUCTURE_ANALYSIS is a deterministic USE/saturation layer built before LLM reasoning. It distinguishes utilization from saturation and records CPU, memory, disk, kernel/system and capacity health with anomaly start time, incident correlation, evidence IDs, causal patterns, gaps and bounded handoff candidates. Treat those features as observations, not automatic root-cause verdicts.

Use the USE model (utilization, saturation, errors) and causal investigation:
- CPU: utilization, load relative to core count, run queue, iowait, steal, throttling, PSI CPU, interrupt/softirq pressure.
- Memory: available memory, working set/cache, swap in/out, major page faults, reclaim, OOM and PSI memory. High used-memory percentage without reclaim/swap/PSI is not sufficient evidence of pressure.
- Disk: utilization, await/latency, queue depth, throughput, IOPS, errors, filesystem capacity, inode pressure and PSI I/O. High utilization without queue/latency/PSI is not automatically a bottleneck.
- Kernel/system: PSI, file descriptors, process count, conntrack, entropy only when relevant, kernel errors, hung tasks and hardware/sensor anomalies.
- Capacity: multi-day baseline, historical percentiles, growth trend and sudden deltas. Do not invent a baseline when none is present.
- Distinguish high-utilization-but-healthy, real saturation, application-driven host pressure, storage bottleneck expressed as iowait, network interrupt pressure, VM steal/noisy-neighbor contention and resource-leak candidates.
- Every finding/hypothesis must cite live evidence and account for anomaly timing relative to incident start when timestamps exist.
- If stronger evidence points to storage/network/vm/application rather than generic infrastructure, prefer the appropriate handoff instead of claiming infrastructure root cause.

For every hypothesis return supporting evidence IDs, conflicting evidence IDs, cheapest read-only falsification checks, impacted components and recommended next evidence.
Return JSON keys: severity, health_status, findings, saturation_signals, capacity_risks, network_signals, node_signals, probable_dependencies, affected_components, blast_radius, hypotheses, missing_evidence, handoff_agents, immediate_checks, escalation_target, risk_level, uncertainty_reason, confidence.
Hypotheses entries: hypothesis, probability, evidence_ids, conflicting_evidence_ids, falsification_checks, impacted_components, recommended_next_evidence. Only LIVE EVIDENCE IDs may be cited. Immediate checks are read-only; restart/reboot/kill/scale/migrate actions are recommendations only and never direct execution.

Incident={input_data.incident_id}\nService={input_data.service_name}\nSummary={input_data.evidence_summary}\nINFRASTRUCTURE_ANALYSIS={json.dumps(sanitize_prompt_value(infrastructure_analysis), default=str)}\nSHARED_DETERMINISTIC_ANALYSIS={json.dumps(deterministic, default=str)}\nLIVE_EVIDENCE={json.dumps(prompt_evidence, default=str)}\nAUXILIARY_CONTEXT={json.dumps(sanitize_prompt_value(auxiliary), default=str)}\nContextSummary={json.dumps(sanitize_prompt_value(input_data.context.get('summary', {})), default=str)}"""
        try:
            result = await self.generate_structured(prompt)
        except Exception as exc:
            logger.error(f"InfrastructureAgent analysis failed: {exc}")
            result = {
                "severity": "unknown",
                "health_status": "unknown",
                "findings": [],
                "saturation_signals": [],
                "capacity_risks": [],
                "network_signals": [],
                "node_signals": [],
                "affected_components": [],
                "blast_radius": "unknown",
                "hypotheses": [],
                "handoff_agents": ["triage"],
                "immediate_checks": ["Collect host USE metrics and system telemetry"],
                "uncertainty_reason": "structured_analysis_failed",
                "confidence": 0.0,
            }
            missing = sorted(set(missing + ["successful structured infrastructure analysis"]))

        deterministic_gap_reasons = [
            str(row.get("reason"))
            for row in infrastructure_analysis.get("evidence_gaps", [])
            if isinstance(row, dict) and row.get("reason")
        ]
        all_missing = sorted(set(missing + self.normalize_list(result.get("missing_evidence"), 8) + deterministic_gap_reasons[:4]))
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

        for target in infrastructure_analysis.get("handoff_candidates", []):
            value = str(target or "")
            if value and value != self.name and value not in handoffs and len(handoffs) < 6:
                handoffs.append(value)
        for hint in deterministic.get("suggested_handoffs", []):
            target = str(hint.get("agent", "")) if isinstance(hint, dict) else ""
            if target and target != self.name and target not in handoffs and len(handoffs) < 6:
                handoffs.append(target)

        for pattern in infrastructure_analysis.get("causal_patterns", []):
            if not isinstance(pattern, dict) or not pattern.get("pattern"):
                continue
            summary = f"Deterministic infrastructure pattern: {pattern['pattern']}"
            if summary not in findings and len(findings) < 10:
                findings.append(summary)

        if not actions:
            actions = [
                f"Collect {row.get('evidence')} because {row.get('reason')}"
                for row in infrastructure_analysis.get("next_best_evidence", [])
                if isinstance(row, dict) and row.get("evidence")
            ][: settings.AGENT_MAX_RECOMMENDATIONS]

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
                "infrastructure_health_matrix": infrastructure_analysis.get("health_matrix", {}),
                "capacity_analysis": infrastructure_analysis.get("capacity_analysis", {}),
                "causal_patterns": infrastructure_analysis.get("causal_patterns", []),
                "metric_kinds": infrastructure_analysis.get("metric_kinds", {}),
                "event_signals": infrastructure_analysis.get("event_signals", {}),
                "evidence_gaps": infrastructure_analysis.get("evidence_gaps", []),
                "next_best_evidence": infrastructure_analysis.get("next_best_evidence", []),
                "deterministic_analysis": deterministic,
                "infrastructure_deterministic_analysis": infrastructure_analysis,
                "saturation_signals": saturation,
                "capacity_risks": result.get("capacity_risks", []),
                "network_signals": result.get("network_signals", []),
                "node_signals": result.get("node_signals", []),
                "metric_evidence_count": len(metrics),
                "alert_evidence_count": len(alerts),
                "telemetry_evidence_count": len(telemetry),
                "knowledge_context_count": len(auxiliary["knowledge_rag"]),
                "memory_context_count": len(auxiliary["operational_memory"]),
                "conflicting_evidence_count": conflict_count,
                "execution_boundary": "analysis_only",
            },
            model_metadata=self._last_model_metadata,
        )
