import json
from typing import List, Optional

from agents.shared.base import AgentInput, AgentOutput, BaseAgent, OperationalHypothesis, RecommendedAction
from domain.contracts.config import settings
from domain.contracts.logging import logger
from integrations.llm.base import LLMAdapter


class VMAgent(BaseAgent):
    def __init__(self, llm_adapter: Optional[LLMAdapter] = None):
        super().__init__(llm_adapter)

    @property
    def name(self) -> str:
        return "vm"

    @property
    def description(self) -> str:
        return "Guest OS diagnostics: reachability, CPU, memory, disk, network, processes, services and system logs"

    @property
    def allowed_tools(self) -> List[str]:
        return ["vm_telemetry", "ssh_readonly", "zabbix_read", "prometheus_query", "knowledge_search"]

    async def analyze(self, input_data: AgentInput) -> AgentOutput:
        logger.info(f"VMAgent analyzing: {input_data.incident_id}")
        evidence = self.evidence_items(input_data)
        evidence_ids = self.evidence_ids(input_data)
        auxiliary = self.auxiliary_context(input_data)
        metrics = [item for item in evidence if str(item.get("type", "")).lower() == "metric"]
        logs = [item for item in evidence if str(item.get("type", "")).lower() == "log"]
        alerts = [item for item in evidence if str(item.get("type", "")).lower() in {"alert", "event"}]
        missing = self.missing_evidence_for(input_data, ["metric", "log"])
        prompt = f"""You are a senior Linux/Windows guest-OS operations analyst. LIVE EVIDENCE is authoritative. RAG/Memory are auxiliary only. Never invent OS/version, process state, CPU/memory/disk numbers, service status, reachability or log content.
Return JSON keys: severity, health_status, findings, reachability, cpu_signals, memory_signals, disk_signals, inode_signals, io_signals, network_signals, process_signals, service_signals, boot_signals, log_signals, probable_dependencies, affected_components, blast_radius, hypotheses, missing_evidence, handoff_agents, immediate_checks, remediation_candidates, escalation_target, risk_level, uncertainty_reason, confidence.
Hypotheses: hypothesis, probability, evidence_ids, conflicting_evidence_ids, falsification_checks, impacted_components, recommended_next_evidence. Only live evidence IDs may be cited. immediate_checks are read-only. remediation_candidates are suggestions only and require Decision/Approval/Execution.
Incident={input_data.incident_id}\nVM/Service={input_data.service_name}\nSummary={input_data.evidence_summary}\nLIVE_EVIDENCE={json.dumps(evidence, default=str)}\nAUXILIARY_CONTEXT={json.dumps(auxiliary, default=str)}\nContextSummary={json.dumps(input_data.context.get('summary', {}), default=str)}"""
        try:
            result = await self.generate_structured(prompt)
        except Exception as exc:
            logger.error(f"VMAgent analysis failed: {exc}")
            result = {"severity":"unknown","health_status":"unknown","findings":[],"reachability":"unknown","affected_components":[],"blast_radius":"unknown","hypotheses":[],"handoff_agents":["infrastructure"],"immediate_checks":["Collect VM telemetry and system logs"],"remediation_candidates":[],"uncertainty_reason":"structured_analysis_failed","confidence":0.0}
            missing = sorted(set(missing + ["successful structured VM analysis"]))

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
        immediate = self.normalize_list(result.get("immediate_checks"), settings.AGENT_MAX_RECOMMENDATIONS)
        remediation = self.normalize_list(result.get("remediation_candidates"), settings.AGENT_MAX_RECOMMENDATIONS)
        severity = str(result.get("severity", "unknown")).lower()
        reachability = str(result.get("reachability", "unknown")).lower()
        write_risk = "high" if reachability in {"unreachable", "stopped"} or severity in {"critical", "high"} else "medium"
        recommended_actions = self.analysis_only_actions(immediate, suggested_tool="vm_telemetry")
        recommended_actions.extend([
            RecommendedAction(action=action, purpose="remediation_candidate", risk_level=write_risk, requires_approval=True, read_only=False, suggested_tool="ssh_vm")
            for action in remediation
        ])
        confirmed = []
        for key in ("cpu_signals", "memory_signals", "disk_signals", "inode_signals", "io_signals", "network_signals", "service_signals", "boot_signals", "log_signals"):
            confirmed.extend(self.normalize_list(result.get(key), 2))
        findings = self.normalize_list(result.get("findings"), 10) or confirmed[:10]
        statement = "VM evidence indicates " + ("; ".join(findings) if findings else "no confirmed guest-OS fault yet")
        return AgentOutput(
            agent_name=self.name,
            finding_type="vm_analysis",
            statement=statement[:600],
            severity=severity,
            health_status=str(result.get("health_status", "unknown")).lower(),
            confidence=confidence,
            evidence_ids=evidence_ids,
            evidence_count=len(evidence),
            evidence_coverage=self.evidence_coverage(len(evidence), all_missing),
            findings=findings,
            recommendations=immediate + remediation,
            recommended_actions=recommended_actions,
            hypotheses=hypotheses,
            missing_evidence=all_missing,
            handoff_agents=self.normalize_list(result.get("handoff_agents"), 6),
            probable_dependencies=self.normalize_list(result.get("probable_dependencies"), 8),
            affected_components=self.normalize_list(result.get("affected_components"), 8),
            blast_radius=str(result.get("blast_radius", "unknown")),
            escalation_target=str(result.get("escalation_target") or "infrastructure-sre"),
            risk_level=str(result.get("risk_level", write_risk if remediation else "low")).lower(),
            uncertainty_reason=str(result.get("uncertainty_reason") or ("missing_evidence" if all_missing else "")) or None,
            requires_approval=bool(remediation),
            requires_human_review=self.human_review_required(confidence, all_missing, severe=severity in {"critical", "high"}),
            analysis_details={
                "reachability": reachability,
                "cpu_signals": result.get("cpu_signals", []),
                "memory_signals": result.get("memory_signals", []),
                "disk_signals": result.get("disk_signals", []),
                "inode_signals": result.get("inode_signals", []),
                "io_signals": result.get("io_signals", []),
                "network_signals": result.get("network_signals", []),
                "process_signals": result.get("process_signals", []),
                "service_signals": result.get("service_signals", []),
                "boot_signals": result.get("boot_signals", []),
                "log_signals": result.get("log_signals", []),
                "metric_evidence_count": len(metrics),
                "log_evidence_count": len(logs),
                "alert_evidence_count": len(alerts),
                "knowledge_context_count": len(auxiliary["knowledge_rag"]),
                "memory_context_count": len(auxiliary["operational_memory"]),
                "conflicting_evidence_count": conflict_count,
            },
            model_metadata=self._last_model_metadata,
        )
