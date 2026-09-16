from __future__ import annotations

import json
import time
from typing import List, Optional

from agents.recovery.engine import build_recovery_readiness_analysis
from agents.shared.base import AgentInput, AgentOutput, OperationalHypothesis
from agents.shared.domain_agent import DomainDiagnosticAgent, DomainSpec
from agents.shared.intelligence import build_deterministic_analysis, sanitize_prompt_value
from domain.contracts.config import settings
from domain.contracts.logging import logger
from integrations.llm.base import LLMAdapter


class RecoveryAgent(DomainDiagnosticAgent):
    spec = DomainSpec(
        name="recovery",
        description="Disaster-Recovery Readiness Analyst for backup usability, RPO/RTO and dependency-ordered recovery",
        focus=[
            "latest successful backup versus latest verified usable restore point",
            "backup freshness/schedule/misses, duration/size anomaly, coverage and retention",
            "snapshot, replication, RPO, RTO, restore-test and integrity verification evidence",
            "encryption-key availability metadata, offsite/secondary and immutable/protected copies",
            "Kubernetes/Velero backup CR, schedule, snapshot/PV coverage and restore history",
            "database base backup, WAL/binlog/transaction-log continuity and failover readiness",
            "storage to database to core dependency to application recovery order",
            "backup succeeded never means recovery is possible without usable restore evidence",
        ],
        required_evidence_types=[],
        read_tools=["elasticsearch_logs", "prometheus_query", "zabbix_read", "knowledge_search"],
        default_handoffs=["storage", "database", "dependency", "application"],
    )

    def __init__(self, llm_adapter: Optional[LLMAdapter] = None):
        super().__init__(llm_adapter)

    async def analyze(self, input_data: AgentInput) -> AgentOutput:
        evidence = self.evidence_items(input_data)
        prompt_evidence = self._prompt_evidence(evidence)
        analyzer_started = time.monotonic()
        deterministic = build_deterministic_analysis(
            self.name, evidence, required_types=self.spec.required_evidence_types, service_name=input_data.service_name
        )
        recovery = build_recovery_readiness_analysis(
            evidence, service_name=input_data.service_name, context=input_data.context or {}
        )
        analyzer_ms = round((time.monotonic() - analyzer_started) * 1000.0, 3)
        evidence_ids = self.evidence_ids(input_data)
        auxiliary_full = self.auxiliary_context(input_data)
        auxiliary = self._bounded_prompt_value(auxiliary_full)
        peer_full = self._peer_context(input_data)
        peer_context = self._bounded_prompt_value(peer_full)
        engine_missing = [
            str(row.get("evidence"))
            for row in recovery.get("next_best_evidence", [])
            if isinstance(row, dict) and row.get("evidence")
        ][: settings.AGENT_MAX_DYNAMIC_EVIDENCE_TYPES]
        missing = sorted(set(self.missing_evidence_for(input_data, []) + engine_missing))
        ceiling = float(recovery.get("confidence_ceiling", 0.45) or 0.45)

        prompt = f"""You are the Disaster-Recovery Readiness Analyst in a production AIOps platform.
LIVE EVIDENCE is authoritative. RECOVERY_READINESS_ANALYSIS is deterministic pre-LLM analysis.
The core rule is: backup succeeded is NOT equivalent to recovery possible. Distinguish the latest successful backup from the latest verified usable restore point.
Assess freshness, expected schedule, missed backups, duration/size anomaly, coverage, retention, restore points, snapshots, replication health/lag, RPO compliance, RTO readiness, restore-test history, integrity evidence, encryption-key availability metadata, dependency recovery order, offsite/secondary copies and immutable/protected copies.
For Kubernetes/Velero evidence assess Backup CR/status, schedule status, snapshot/PV coverage, restore history and partial failures.
For database evidence assess base backup, WAL/binlog/transaction-log continuity and replication/failover readiness.
Use potential_data_loss_window_seconds only from incident time minus verified usable restore point. If restore was never tested, do not give high recoverability confidence.
Never expose encryption key material. Only availability metadata is relevant.
Never execute restore or failover. Any recovery action requires human decision plus the platform approval path.
DETERMINISTIC confidence ceiling={ceiling}. Do not exceed it.
Return one JSON object with keys: severity, health_status, findings, affected_components, probable_dependencies, blast_radius, hypotheses, missing_evidence, handoff_agents, immediate_checks, escalation_target, risk_level, uncertainty_reason, confidence.
Each hypothesis: hypothesis, probability, evidence_ids, conflicting_evidence_ids, falsification_checks, impacted_components, recommended_next_evidence.
Only cite LIVE EVIDENCE IDs. immediate_checks are read-only.
Incident={input_data.incident_id}
Service={input_data.service_name}
Summary={input_data.evidence_summary}
RECOVERY_READINESS_ANALYSIS={json.dumps(sanitize_prompt_value(recovery), default=str)}
DETERMINISTIC_ANALYSIS={json.dumps(sanitize_prompt_value(deterministic), default=str)}
LIVE_EVIDENCE={json.dumps(prompt_evidence, default=str)}
AUXILIARY_CONTEXT={json.dumps(auxiliary, default=str)}
PEER_OPERATIONAL_CONTEXT={json.dumps(peer_context, default=str)}"""

        structured_failed = False
        try:
            result = await self.generate_structured(prompt)
        except Exception as exc:
            structured_failed = True
            logger.error(f"recovery structured analysis failed: {exc}")
            result = {
                "severity": "unknown", "health_status": "unknown",
                "findings": [], "affected_components": [], "probable_dependencies": [],
                "blast_radius": "unknown", "hypotheses": [],
                "missing_evidence": ["successful structured recovery synthesis"],
                "handoff_agents": [], "immediate_checks": ["Inspect verified restore history and RPO/RTO evidence"],
                "escalation_target": "recovery-operator", "risk_level": "low",
                "uncertainty_reason": "structured_analysis_failed", "confidence": 0.0,
            }

        all_missing = sorted(set(missing + self.normalize_list(result.get("missing_evidence"), 8)))
        hypotheses: List[OperationalHypothesis] = []
        conflicts = 0
        for item in result.get("hypotheses", [])[: settings.AGENT_MAX_HYPOTHESES]:
            if not isinstance(item, dict) or not item.get("hypothesis"):
                continue
            conflicting = [str(value) for value in item.get("conflicting_evidence_ids", []) if str(value) in evidence_ids]
            conflicts += len(conflicting)
            probability = self.safe_confidence(item.get("probability", 0), len(evidence), all_missing, len(conflicting))
            hypotheses.append(OperationalHypothesis(
                hypothesis=str(item["hypothesis"]),
                probability=min(probability, ceiling),
                evidence_ids=[str(value) for value in item.get("evidence_ids", []) if str(value) in evidence_ids],
                conflicting_evidence_ids=conflicting,
                falsification_checks=self.normalize_list(item.get("falsification_checks"), 5),
                impacted_components=self.normalize_list(item.get("impacted_components"), 6),
                recommended_next_evidence=self.normalize_list(item.get("recommended_next_evidence"), 6),
            ))

        confidence = min(self.safe_confidence(result.get("confidence"), len(evidence), all_missing, conflicts), ceiling)
        findings = self.normalize_list(result.get("findings"), 10)
        actions = self.normalize_list(result.get("immediate_checks"), settings.AGENT_MAX_RECOMMENDATIONS)
        handoffs = self.normalize_list(result.get("handoff_agents"), 6)
        for target in self.spec.default_handoffs:
            if target not in handoffs and len(handoffs) < 6:
                handoffs.append(target)

        latest_backup = recovery.get("latest_backup") or {}
        latest_verified = recovery.get("latest_verified_restore_point") or {}
        uncertainty = str(result.get("uncertainty_reason") or "")
        if recovery.get("restore_validation_status") == "untested":
            reason = "restore_untested_recoverability_not_demonstrated"
            uncertainty = reason if not uncertainty else f"{uncertainty}; {reason}"

        return AgentOutput(
            agent_name=self.name,
            finding_type="recovery_readiness_analysis",
            statement=("Recovery evidence: " + ("; ".join(findings) if findings else "recoverability requires verified restore evidence"))[:600],
            severity=str(result.get("severity", "unknown")).lower(),
            health_status=str(result.get("health_status", "unknown")).lower(),
            confidence=confidence,
            evidence_ids=evidence_ids,
            evidence_count=len(evidence),
            evidence_coverage=self.evidence_coverage(len(evidence), all_missing),
            findings=findings,
            recommendations=actions,
            recommended_actions=self.analysis_only_actions(actions, self.spec.read_tools[0]),
            hypotheses=hypotheses,
            missing_evidence=all_missing,
            handoff_agents=handoffs,
            probable_dependencies=self.normalize_list(result.get("probable_dependencies"), 8),
            affected_components=self.normalize_list(result.get("affected_components"), 8),
            blast_radius=str(result.get("blast_radius", "unknown")),
            escalation_target=str(result.get("escalation_target") or "recovery-operator"),
            risk_level=str(result.get("risk_level", "low")).lower(),
            uncertainty_reason=uncertainty or None,
            requires_human_review=True,
            analysis_details={
                "focus": self.spec.focus,
                "recovery_analysis": recovery,
                "latest_backup": latest_backup.get("timestamp"),
                "latest_verified_restore_point": latest_verified.get("timestamp"),
                "potential_data_loss_window_seconds": recovery.get("potential_data_loss_window_seconds"),
                "rpo_status": recovery.get("rpo_status"),
                "rto_risk": recovery.get("rto_risk"),
                "coverage_gaps": recovery.get("coverage_gaps", []),
                "restore_validation_status": ("verified_restore_point_available" if recovery.get("restore_validation_status") == "verified" else "restore_validation_missing" if recovery.get("restore_validation_status") == "untested" else recovery.get("restore_validation_status")),
                "recovery_sequence": recovery.get("recovery_sequence", []),
                "recovery_dependency_graph": recovery.get("recovery_dependency_graph", {}),
                "human_decision_required": True,
                "execution_policy": "analysis_only; restore/failover require Evaluator -> Policy -> Approval -> Execution -> Verification",
                "confidence_ceiling": ceiling,
                "deterministic_analysis": deterministic,
                "shared_deterministic_analysis": deterministic,
                "next_best_evidence": recovery.get("next_best_evidence", []),
                "stale_evidence_ids": self.stale_evidence_ids(input_data),
                "analyzer_telemetry": {
                    "analyzer": "recovery_readiness",
                    "duration_ms": analyzer_ms,
                    "evidence_count": len(evidence),
                },
                "knowledge_context_count": len(auxiliary_full["knowledge_rag"]),
                "memory_context_count": len(auxiliary_full["operational_memory"]),
                "peer_finding_count": len(peer_full["findings"]),
                "peer_disagreement": bool(peer_full["coordination"].get("disagreement")),
                "conflicting_evidence_count": conflicts,
                "prompt_evidence_count": len(prompt_evidence),
                "structured_analysis_failed": structured_failed,
                "execution_boundary": "analysis_only_no_restore_or_failover",
                "readiness_policy": recovery.get("policy"),
            },
            model_metadata=self._last_model_metadata,
        )
