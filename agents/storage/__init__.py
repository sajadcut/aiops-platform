from __future__ import annotations

import json
from typing import List, Optional

from agents.shared.base import AgentInput, AgentOutput, OperationalHypothesis
from agents.shared.domain_agent import DomainDiagnosticAgent, DomainSpec
from agents.shared.intelligence import build_deterministic_analysis, sanitize_prompt_value
from agents.storage.engine import build_storage_reliability_analysis
from domain.contracts.config import settings
from domain.contracts.logging import logger
from integrations.llm.base import LLMAdapter


class StorageAgent(DomainDiagnosticAgent):
    spec = DomainSpec(
        name="storage",
        description="Deep Storage Reliability Investigator with deterministic device, filesystem, path and distributed-storage analysis",
        focus=[
            "capacity percentage, growth rate and inode utilization",
            "IOPS, throughput, latency/await, queue depth, utilization and throttling",
            "device errors, filesystem errors, read-only state and mount health",
            "NVMe/SATA/SCSI and SMART indicators as probabilistic evidence rather than certainty",
            "multipath/path failures and persistent-volume attach/mount symptoms",
            "Ceph OSD/PG/degraded/slow-op/recovery/backfill/replica health when supplied",
            "disk full, inode full, I/O saturation, device failure, networked-storage latency and filesystem corruption separation",
            "application write burst and database-driven storage pressure versus storage-originated failure",
            "storage anomaly timing against application/database incident timing",
        ],
        required_evidence_types=["metric"],
        read_tools=["prometheus_query", "zabbix_read", "vm_telemetry", "kubectl_get", "knowledge_search"],
        default_handoffs=["infrastructure", "database", "application", "kubernetes", "network", "recovery"],
    )

    def __init__(self, llm_adapter: Optional[LLMAdapter] = None):
        super().__init__(llm_adapter)

    async def analyze(self, input_data: AgentInput) -> AgentOutput:
        evidence = self.evidence_items(input_data)
        raw_evidence = input_data.context.get("evidence", []) if input_data.context else []
        deterministic_evidence = [
            item for item in raw_evidence
            if isinstance(item, dict) and not self.evidence_is_stale(item)
        ] if isinstance(raw_evidence, list) else []
        prompt_evidence = self._prompt_evidence(evidence)
        deterministic = build_deterministic_analysis(
            self.name,
            deterministic_evidence,
            required_types=self.spec.required_evidence_types,
            service_name=input_data.service_name,
        )
        storage_context = dict(input_data.context or {})
        if input_data.time_range and "time_range" not in storage_context:
            storage_context["time_range"] = input_data.time_range
        storage_analysis = build_storage_reliability_analysis(
            deterministic_evidence,
            service_name=input_data.service_name,
            context=storage_context,
        )
        evidence_ids = self.evidence_ids(input_data)
        auxiliary_full = self.auxiliary_context(input_data)
        auxiliary = self._bounded_prompt_value(auxiliary_full)
        peer_full = self._peer_context(input_data)
        peer_context = self._bounded_prompt_value(peer_full)
        missing = self.missing_evidence_for(input_data, self.spec.required_evidence_types)

        prompt = f"""You are the storage specialist and a senior Storage Reliability Investigator in a production AIOps platform.
LIVE EVIDENCE is authoritative. RAG/Memory and PEER OPERATIONAL CONTEXT are auxiliary only. Never inherit peer confidence or causal conclusions and never invent current state.
STORAGE_ANALYSIS is deterministic pre-LLM analysis across capacity/inodes, I/O performance, filesystem/mount, device/SMART, multipath/PV, distributed storage and temporal correlation. Treat cause candidates as hypotheses requiring falsification, not automatic root-cause verdicts.
Critical device-health rule: a SMART warning does not mean a disk is certainly or imminently failing. State the observed indicator, confidence and verification required. Stronger physical-device attribution requires corroborating media/I/O/NVMe/SCSI evidence.
Explicitly distinguish disk full, inode full, I/O saturation, failing physical device, networked-storage latency, filesystem corruption symptoms, application write burst and database-driven storage pressure. A storage alert alone is not proof that storage is the primary cause.
Use STORAGE_ANALYSIS.temporal_correlation to compare storage anomaly onset with application/database incident timing. Temporal ordering supports falsification but does not prove causality. If application/database write pressure precedes storage pressure, consider storage as a downstream stressed resource; if storage/device/path faults precede application/database symptoms, storage becomes a stronger cause candidate.
When Ceph evidence exists, inspect OSD state, PG health, degraded state, slow ops, recovery/backfill and replica health. When Kubernetes storage evidence exists, inspect PV/PVC state and attach/mount symptoms. Do not invent Ceph, SMART, multipath or PV state when absent.
Focus areas: {json.dumps(self.spec.focus)}
Return one JSON object with keys: severity, health_status, findings, affected_components,
probable_dependencies, blast_radius, hypotheses, missing_evidence, handoff_agents,
immediate_checks, escalation_target, risk_level, uncertainty_reason, confidence.
Each hypothesis: hypothesis, probability, evidence_ids, conflicting_evidence_ids,
falsification_checks, impacted_components, recommended_next_evidence.
Only cite LIVE EVIDENCE IDs. immediate_checks are read-only. Destructive actions such as deleting files, filesystem repair, detach/attach, failover or device replacement may only be recommendations subject to approval and must never be executed directly.
Incident={input_data.incident_id}
Service={input_data.service_name}
Summary={input_data.evidence_summary}
STORAGE_ANALYSIS={json.dumps(sanitize_prompt_value(storage_analysis), default=str)}
DETERMINISTIC_ANALYSIS={json.dumps(sanitize_prompt_value(deterministic), default=str)}
LIVE_EVIDENCE={json.dumps(prompt_evidence, default=str)}
AUXILIARY_CONTEXT={json.dumps(auxiliary, default=str)}
PEER_OPERATIONAL_CONTEXT={json.dumps(peer_context, default=str)}"""

        structured_failed = False
        try:
            result = await self.generate_structured(prompt)
        except Exception as exc:
            structured_failed = True
            logger.error(f"storage structured analysis failed: {exc}")
            causal_codes = [
                str(row.get("code")) for row in storage_analysis.get("cause_candidates", [])
                if isinstance(row, dict) and row.get("code")
            ]
            result = {
                "severity": "unknown",
                "health_status": "unknown",
                "findings": causal_codes[:8],
                "affected_components": [input_data.service_name] if input_data.service_name else [],
                "probable_dependencies": [],
                "blast_radius": "unknown",
                "hypotheses": [],
                "missing_evidence": ["successful structured storage analysis"],
                "handoff_agents": list(storage_analysis.get("handoff_candidates") or self.spec.default_handoffs),
                "immediate_checks": ["Collect capacity, inode, I/O latency/queue/utilization, device and path health evidence"],
                "escalation_target": "storage-operator",
                "risk_level": "low",
                "uncertainty_reason": "structured_analysis_failed",
                "confidence": 0.0,
            }

        all_missing = sorted(set(missing + self.normalize_list(result.get("missing_evidence"), 8)))
        hypotheses: List[OperationalHypothesis] = []
        conflicts = 0
        for item in result.get("hypotheses", [])[: settings.AGENT_MAX_HYPOTHESES]:
            if not isinstance(item, dict) or not item.get("hypothesis"):
                continue
            conflicting = [str(x) for x in item.get("conflicting_evidence_ids", []) if str(x) in evidence_ids]
            conflicts += len(conflicting)
            hypotheses.append(OperationalHypothesis(
                hypothesis=str(item["hypothesis"]),
                probability=self.safe_confidence(item.get("probability", 0), len(evidence), all_missing, len(conflicting)),
                evidence_ids=[str(x) for x in item.get("evidence_ids", []) if str(x) in evidence_ids],
                conflicting_evidence_ids=conflicting,
                falsification_checks=self.normalize_list(item.get("falsification_checks"), 5),
                impacted_components=self.normalize_list(item.get("impacted_components"), 6),
                recommended_next_evidence=self.normalize_list(item.get("recommended_next_evidence"), 6),
            ))

        confidence = self.safe_confidence(result.get("confidence"), len(evidence), all_missing, conflicts)
        findings = self.normalize_list(result.get("findings"), 10)
        if structured_failed and not findings:
            findings = [
                str(row.get("code")) for row in storage_analysis.get("cause_candidates", [])
                if isinstance(row, dict) and row.get("code")
            ][:10]
        actions = self.normalize_list(result.get("immediate_checks"), settings.AGENT_MAX_RECOMMENDATIONS)
        coverage = self.evidence_coverage(len(evidence), all_missing)
        handoffs = self.normalize_list(result.get("handoff_agents"), 6)
        for target in storage_analysis.get("handoff_candidates", []):
            target = str(target)
            if target and target != self.name and target not in handoffs and len(handoffs) < 6:
                handoffs.append(target)
        for hint in deterministic.get("suggested_handoffs", []):
            target = str(hint.get("agent", "")) if isinstance(hint, dict) else ""
            if target and target != self.name and target not in handoffs and len(handoffs) < 6:
                handoffs.append(target)
        if not handoffs:
            handoffs = list(self.spec.default_handoffs)

        return AgentOutput(
            agent_name=self.name,
            finding_type="storage_analysis",
            statement=("Storage evidence: " + ("; ".join(findings) if findings else "no confirmed storage-local fault yet"))[:600],
            severity=str(result.get("severity", "unknown")).lower(),
            health_status=str(result.get("health_status", "unknown")).lower(),
            confidence=confidence,
            evidence_ids=evidence_ids,
            evidence_count=len(evidence),
            evidence_coverage=coverage,
            findings=findings,
            recommendations=actions,
            recommended_actions=self.analysis_only_actions(actions, self.spec.read_tools[0] if self.spec.read_tools else None),
            hypotheses=hypotheses,
            missing_evidence=all_missing,
            handoff_agents=handoffs,
            probable_dependencies=self.normalize_list(result.get("probable_dependencies"), 8),
            affected_components=self.normalize_list(result.get("affected_components"), 8),
            blast_radius=str(result.get("blast_radius", "unknown")),
            escalation_target=str(result.get("escalation_target") or "storage-operator"),
            risk_level=str(result.get("risk_level", "low")).lower(),
            uncertainty_reason=str(result.get("uncertainty_reason") or ("missing_evidence" if all_missing else "")) or None,
            requires_human_review=self.human_review_required(confidence, all_missing),
            analysis_details={
                "focus": self.spec.focus,
                "storage_analysis": storage_analysis,
                "capacity_analysis": storage_analysis.get("capacity_analysis", {}),
                "io_analysis": storage_analysis.get("io_analysis", {}),
                "filesystem_analysis": storage_analysis.get("filesystem_analysis", {}),
                "device_health_analysis": storage_analysis.get("device_health_analysis", {}),
                "path_analysis": storage_analysis.get("path_analysis", {}),
                "distributed_storage_analysis": storage_analysis.get("distributed_storage_analysis", {}),
                "temporal_correlation": storage_analysis.get("temporal_correlation", {}),
                "cause_candidates": storage_analysis.get("cause_candidates", []),
                "causal_attribution": storage_analysis.get("causal_attribution"),
                "evidence_gap_matrix": deterministic.get("evidence_gap_matrix", {}),
                "next_best_evidence": storage_analysis.get("next_best_evidence", []),
                "deterministic_analysis": deterministic,
                "shared_deterministic_analysis": deterministic,
                "knowledge_context_count": len(auxiliary_full["knowledge_rag"]),
                "memory_context_count": len(auxiliary_full["operational_memory"]),
                "peer_finding_count": len(peer_full["findings"]),
                "peer_disagreement": bool(peer_full["coordination"].get("disagreement")),
                "conflicting_evidence_count": conflicts,
                "prompt_evidence_count": len(prompt_evidence),
                "deterministic_evidence_count": len(deterministic_evidence),
                "structured_analysis_failed": structured_failed,
                "execution_boundary": "analysis_only",
                "smart_policy": storage_analysis.get("smart_policy"),
                "causal_policy": storage_analysis.get("policy"),
            },
            model_metadata=self._last_model_metadata,
        )
