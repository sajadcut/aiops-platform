import json
from typing import List, Optional

from agents.shared.base import AgentInput, AgentOutput, BaseAgent, OperationalHypothesis, RecommendedAction
from agents.shared.domain_agent import DomainDiagnosticAgent
from agents.shared.intelligence import build_deterministic_analysis, sanitize_prompt_value
from agents.vm.deterministic import classify_vm_service_fault
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
        # Prompt evidence stays bounded, but deterministic operational checks must
        # inspect every fresh live-evidence item. Otherwise a high-volume incident
        # can push the decisive service/process/config/port rows beyond
        # AGENT_MAX_EVIDENCE_ITEMS and silently disable deterministic recovery.
        evidence = self.evidence_items(input_data)
        raw_evidence = input_data.context.get("evidence", []) if input_data.context else []
        deterministic_evidence = [
            item for item in raw_evidence
            if isinstance(item, dict) and not self.evidence_is_stale(item)
        ] if isinstance(raw_evidence, list) else []
        prompt_evidence = DomainDiagnosticAgent._prompt_evidence(evidence)
        deterministic_fault = classify_vm_service_fault(deterministic_evidence, input_data.service_name)
        deterministic_analysis = build_deterministic_analysis("vm", deterministic_evidence, ["metric", "log"], input_data.service_name)
        evidence_ids = self.evidence_ids(input_data)
        if deterministic_fault:
            evidence_ids = list(dict.fromkeys(evidence_ids + list(deterministic_fault.get("evidence_ids") or [])))
        auxiliary_full = self.auxiliary_context(input_data)
        auxiliary = sanitize_prompt_value(auxiliary_full)
        context_summary = sanitize_prompt_value(input_data.context.get("summary", {}))
        metrics = [item for item in evidence if str(item.get("type", "")).lower() == "metric"]
        logs = [item for item in evidence if str(item.get("type", "")).lower() == "log"]
        alerts = [item for item in evidence if str(item.get("type", "")).lower() in {"alert", "event"}]
        missing = self.missing_evidence_for(input_data, ["metric", "log"])
        prompt = f"""You are a senior Linux/Windows guest-OS reliability investigator. LIVE EVIDENCE is authoritative. RAG/Memory are auxiliary only. Never invent OS/version, process state, CPU/memory/disk numbers, service status, reachability, human action or log content.
Follow this diagnostic chain whenever evidence permits: host reachable -> OS healthy -> service state -> process alive -> expected port listening/bind address -> local TCP -> remote TCP -> DNS/route/path. Also inspect CPU/load/iowait/steal, memory/swap/PSI/OOM, disk/inode/I/O/filesystem, boot/reboot chronology, process parent/child/resource/FD/socket state, systemd load/active/sub/result/main PID/exit/restart/failed dependencies, journal/kernel errors, clock skew and ulimit pressure. Keep Windows Service Control Manager/Event Log equivalents as a supported evidence model when Windows telemetry is present.
Critical rule: inactive/dead service or zero/success exit status NEVER proves a human manually stopped it. Human action may be asserted only when explicit journal/audit/system evidence identifies the actor/action. Distinguish crash, dependency failure, boot-time non-start, config error, port conflict and network-path failure.
DETERMINISTIC_ANALYSIS is an observation index and gap planner; DETERMINISTIC_SERVICE_FAULT is a bounded rule-based service diagnosis when direct evidence satisfies it. Neither grants write authority. remediation_candidates are suggestions only.
Return JSON keys: severity, health_status, findings, reachability, cpu_signals, memory_signals, disk_signals, inode_signals, io_signals, network_signals, process_signals, service_signals, boot_signals, log_signals, probable_dependencies, affected_components, blast_radius, hypotheses, missing_evidence, handoff_agents, immediate_checks, remediation_candidates, escalation_target, risk_level, uncertainty_reason, confidence.
Hypotheses: hypothesis, probability, evidence_ids, conflicting_evidence_ids, falsification_checks, impacted_components, recommended_next_evidence. Only live evidence IDs may be cited. immediate_checks are read-only. remediation_candidates require Decision/Approval/Execution.
Incident={input_data.incident_id}\nVM/Service={input_data.service_name}\nSummary={input_data.evidence_summary}\nDETERMINISTIC_ANALYSIS={json.dumps(deterministic_analysis, default=str)}\nDETERMINISTIC_SERVICE_FAULT={json.dumps(sanitize_prompt_value(deterministic_fault or {}), default=str)}\nLIVE_EVIDENCE={json.dumps(prompt_evidence, default=str)}\nAUXILIARY_CONTEXT={json.dumps(auxiliary, default=str)}\nContextSummary={json.dumps(context_summary, default=str)}"""
        structured_failed = False
        try:
            result = await self.generate_structured(prompt)
        except Exception as exc:
            structured_failed = True
            logger.error(f"VMAgent analysis failed: {exc}")
            if deterministic_fault:
                result = {
                    "severity": deterministic_fault["severity"],
                    "health_status": deterministic_fault["health_status"],
                    "findings": list(deterministic_fault["findings"]),
                    "reachability": "reachable",
                    "affected_components": [input_data.service_name] if input_data.service_name else [],
                    "blast_radius": "service",
                    "hypotheses": [deterministic_fault["hypothesis"]],
                    "handoff_agents": [],
                    "immediate_checks": [],
                    "remediation_candidates": [deterministic_fault["remediation_candidate"]],
                    "uncertainty_reason": None,
                    "confidence": deterministic_fault["confidence"],
                }
            else:
                result = {"severity":"unknown","health_status":"unknown","findings":[],"reachability":"unknown","affected_components":[],"blast_radius":"unknown","hypotheses":[],"handoff_agents":["infrastructure"],"immediate_checks":["Collect VM telemetry and system logs"],"remediation_candidates":[],"uncertainty_reason":"structured_analysis_failed","confidence":0.0}
                missing = sorted(set(missing + ["successful structured VM analysis"]))

        if deterministic_fault and not structured_failed:
            result["findings"] = self.normalize_list(
                list(result.get("findings") or []) + list(deterministic_fault["findings"]), 10
            )
            existing_hypotheses = list(result.get("hypotheses") or [])
            if not any(
                isinstance(item, dict)
                and str(item.get("hypothesis") or "").strip().lower()
                == str(deterministic_fault["hypothesis"]["hypothesis"]).strip().lower()
                for item in existing_hypotheses
            ):
                existing_hypotheses.insert(0, deterministic_fault["hypothesis"])
            result["hypotheses"] = existing_hypotheses
            result["remediation_candidates"] = self.normalize_list(
                list(result.get("remediation_candidates") or []) + [deterministic_fault["remediation_candidate"]],
                settings.AGENT_MAX_RECOMMENDATIONS,
            )
            result["health_status"] = "unhealthy"
            if str(result.get("severity") or "unknown").lower() == "unknown":
                result["severity"] = deterministic_fault["severity"]

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
        if deterministic_fault:
            deterministic_confidence = self.safe_confidence(
                deterministic_fault["confidence"], len(evidence), all_missing, 0
            )
            confidence = max(confidence, deterministic_confidence)
        immediate = self.normalize_list(result.get("immediate_checks"), settings.AGENT_MAX_RECOMMENDATIONS)
        remediation = self.normalize_list(result.get("remediation_candidates"), settings.AGENT_MAX_RECOMMENDATIONS)
        severity = str(result.get("severity", "unknown")).lower()
        reachability = str(result.get("reachability", "unknown")).lower()
        write_risk = "high" if reachability in {"unreachable", "stopped"} or severity in {"critical", "high"} else "medium"
        recommended_actions = self.analysis_only_actions(immediate, suggested_tool="vm_telemetry")
        recommended_actions.extend([
            RecommendedAction(action=action, purpose="remediation_candidate", risk_level="high", requires_approval=True, read_only=False, suggested_tool="ssh_vm")
            for action in remediation
        ])
        if deterministic_fault and not any(action.action == deterministic_fault["suggested_action"] for action in recommended_actions):
            recommended_actions.append(RecommendedAction(
                action=deterministic_fault["suggested_action"],
                purpose="deterministic_remediation_candidate",
                risk_level="high",
                requires_approval=True,
                read_only=False,
                suggested_tool="ssh_vm",
                expected_evidence=["service active", "expected port listening", "original TCP symptom recovered"],
            ))
        confirmed = []
        for key in ("cpu_signals", "memory_signals", "disk_signals", "inode_signals", "io_signals", "network_signals", "service_signals", "boot_signals", "log_signals"):
            confirmed.extend(self.normalize_list(result.get(key), 2))
        findings = self.normalize_list(result.get("findings"), 10) or confirmed[:10]
        handoffs = self.normalize_list(result.get("handoff_agents"), 6)
        for hint in deterministic_analysis.get("suggested_handoffs", []):
            target = str(hint.get("agent", "")) if isinstance(hint, dict) else ""
            if target and target != self.name and target not in handoffs and len(handoffs) < 6:
                handoffs.append(target)
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
            handoff_agents=handoffs,
            probable_dependencies=self.normalize_list(result.get("probable_dependencies"), 8),
            affected_components=self.normalize_list(result.get("affected_components"), 8),
            blast_radius=str(result.get("blast_radius", "unknown")),
            escalation_target=str(result.get("escalation_target") or "infrastructure-sre"),
            risk_level=str(result.get("risk_level", write_risk if remediation else "low")).lower(),
            uncertainty_reason=str(result.get("uncertainty_reason") or ("missing_evidence" if all_missing else "")) or None,
            requires_approval=bool(remediation or deterministic_fault),
            requires_human_review=self.human_review_required(confidence, all_missing, severe=severity == "critical"),
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
                "deterministic_analysis": deterministic_analysis,
                "diagnostic_chain": deterministic_analysis.get("playbook_checks", []),
                "network_paths": deterministic_analysis.get("network_paths", []),
                "next_best_evidence": deterministic_analysis.get("next_best_evidence", []),
                "metric_evidence_count": len(metrics),
                "log_evidence_count": len(logs),
                "alert_evidence_count": len(alerts),
                "knowledge_context_count": len(auxiliary_full["knowledge_rag"]),
                "memory_context_count": len(auxiliary_full["operational_memory"]),
                "conflicting_evidence_count": conflict_count,
                "prompt_evidence_count": len(prompt_evidence),
                "deterministic_evidence_count": len(deterministic_evidence),
                "deterministic_fault": deterministic_fault.get("fault_code") if deterministic_fault else None,
                "structured_analysis_failed": structured_failed,
            },
            model_metadata=self._last_model_metadata,
        )