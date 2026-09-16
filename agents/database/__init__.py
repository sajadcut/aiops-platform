from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

from agents.database.engine import build_database_reliability_analysis, database_prompt_evidence_projection
from agents.shared.base import AgentInput, AgentOutput, OperationalHypothesis
from agents.shared.domain_agent import DomainDiagnosticAgent, DomainSpec
from agents.shared.intelligence import build_deterministic_analysis, sanitize_prompt_value
from domain.contracts.config import settings
from domain.contracts.logging import logger
from integrations.llm.base import LLMAdapter


class DatabaseAgent(DomainDiagnosticAgent):
    spec = DomainSpec(
        name="database",
        description="Database Reliability Investigator with common cross-vendor analysis and PostgreSQL-specific evidence adaptation",
        focus=[
            "connection count/utilization, pool exhaustion and rejected connections",
            "query latency/throughput/error rate, normalized fingerprints and long-running transactions",
            "locks, deadlocks, wait events and transaction duration",
            "replication health/lag and restart/failover chronology",
            "storage latency, disk capacity, CPU/memory saturation and cache/buffer behavior",
            "checkpoint/WAL symptoms and database error logs",
            "application connection storms versus database-local faults",
            "slow query, lock contention, CPU saturation, storage latency, replication, network, downstream dependency and capacity exhaustion",
        ],
        required_evidence_types=["metric", "log"],
        read_tools=["prometheus_query", "elasticsearch_logs", "zabbix_read", "knowledge_search"],
        default_handoffs=["application", "storage", "infrastructure", "recovery", "dependency", "network"],
    )

    def __init__(self, llm_adapter: Optional[LLMAdapter] = None):
        super().__init__(llm_adapter)

    @classmethod
    def _prompt_evidence(cls, evidence: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        return database_prompt_evidence_projection(evidence, settings.AGENT_MAX_EVIDENCE_ITEMS)

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
        database_analysis = build_database_reliability_analysis(
            deterministic_evidence,
            service_name=input_data.service_name,
            context=input_data.context or {},
        )
        evidence_ids = self.evidence_ids(input_data)
        auxiliary_full = self.auxiliary_context(input_data)
        auxiliary = self._bounded_prompt_value(auxiliary_full)
        peer_full = self._peer_context(input_data)
        peer_context = self._bounded_prompt_value(peer_full)
        missing = self.missing_evidence_for(input_data, self.spec.required_evidence_types)
        prompt = f"""You are the database specialist and a senior Database Reliability Investigator in a production AIOps platform.
LIVE EVIDENCE is authoritative. RAG/Memory and PEER OPERATIONAL CONTEXT are auxiliary only. Never inherit a peer confidence or causal conclusion. Never invent current state.
DATABASE_ANALYSIS is deterministic pre-LLM feature extraction. It computes connection/pool state, top normalized query fingerprints, top waits, biggest incident-vs-baseline deltas, resource/replication/event features and bounded cause candidates. These are observations and hypotheses to falsify, never an automatic root-cause verdict.
Critical query-safety rule: raw query text, SQL literal values and bind parameters must not appear in your answer, prompt reasoning, findings or logs. Use only normalized query fingerprints/query IDs already provided in DATABASE_ANALYSIS/LIVE_EVIDENCE.
For PostgreSQL, reason from available pg_stat_activity, pg_stat_statements-equivalent aggregates, locks/deadlocks/wait events, replication lag, vacuum/autovacuum and WAL/checkpoint evidence. Do not assume PostgreSQL when vendor evidence is absent.
Compare the real-time incident window with historical/pre-incident baseline whenever deltas are available. Explicitly distinguish: application connection storm, slow query, lock contention, DB CPU saturation, storage-induced latency, replication issue, network connectivity, downstream dependency and capacity exhaustion.
A database alert is only a symptom. Do not declare the database root cause merely because this agent received a database alert. Prefer cross-layer evidence, conflicting evidence and the cheapest falsification check. Handoff to application/storage/network/dependency/recovery/infrastructure when their evidence is stronger.
Focus areas: {json.dumps(self.spec.focus)}
Run the shared playbook in DETERMINISTIC_ANALYSIS.playbook_checks as a secondary coverage checklist.
Return one JSON object with keys: severity, health_status, findings, affected_components,
probable_dependencies, blast_radius, hypotheses, missing_evidence, handoff_agents,
immediate_checks, escalation_target, risk_level, uncertainty_reason, confidence.
Each hypothesis: hypothesis, probability, evidence_ids, conflicting_evidence_ids,
falsification_checks, impacted_components, recommended_next_evidence.
Only cite LIVE EVIDENCE IDs. immediate_checks are read-only. Request missing factual state instead of guessing it.
Incident={input_data.incident_id}
Service={input_data.service_name}
Summary={input_data.evidence_summary}
DATABASE_ANALYSIS={json.dumps(sanitize_prompt_value(database_analysis), default=str)}
DETERMINISTIC_ANALYSIS={json.dumps(sanitize_prompt_value(deterministic), default=str)}
LIVE_EVIDENCE={json.dumps(prompt_evidence, default=str)}
AUXILIARY_CONTEXT={json.dumps(auxiliary, default=str)}
PEER_OPERATIONAL_CONTEXT={json.dumps(peer_context, default=str)}"""
        structured_failed = False
        try:
            result = await self.generate_structured(prompt)
        except Exception as exc:
            structured_failed = True
            logger.error(f"database structured analysis failed: {exc}")
            causal_codes = [
                str(row.get("code")) for row in database_analysis.get("cause_candidates", [])
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
                "missing_evidence": ["successful structured database analysis"],
                "handoff_agents": list(database_analysis.get("handoff_candidates") or self.spec.default_handoffs),
                "immediate_checks": ["Collect database incident-window metrics, error logs, waits and normalized query statistics"],
                "escalation_target": "database-operator",
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
                str(row.get("code")) for row in database_analysis.get("cause_candidates", [])
                if isinstance(row, dict) and row.get("code")
            ][:10]
        actions = self.normalize_list(result.get("immediate_checks"), settings.AGENT_MAX_RECOMMENDATIONS)
        coverage = self.evidence_coverage(len(evidence), all_missing)
        handoffs = self.normalize_list(result.get("handoff_agents"), 6)
        for target in database_analysis.get("handoff_candidates", []):
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
            finding_type="database_analysis",
            statement=("Database evidence: " + ("; ".join(findings) if findings else "no confirmed database-local fault yet"))[:600],
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
            escalation_target=str(result.get("escalation_target") or "database-operator"),
            risk_level=str(result.get("risk_level", "low")).lower(),
            uncertainty_reason=str(result.get("uncertainty_reason") or ("missing_evidence" if all_missing else "")) or None,
            requires_human_review=self.human_review_required(confidence, all_missing),
            analysis_details={
                "focus": self.spec.focus,
                "database_analysis": database_analysis,
                "connection_analysis": database_analysis.get("connection_analysis", {}),
                "top_query_fingerprints": database_analysis.get("query_analysis", {}).get("top_query_fingerprints", []),
                "top_waits": database_analysis.get("contention_analysis", {}).get("top_waits", []),
                "biggest_temporal_deltas": database_analysis.get("biggest_temporal_deltas", []),
                "cause_candidates": database_analysis.get("cause_candidates", []),
                "postgresql_analysis": database_analysis.get("postgresql", {}),
                "evidence_gap_matrix": deterministic.get("evidence_gap_matrix", {}),
                "next_best_evidence": database_analysis.get("next_best_evidence", []),
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
                "query_text_policy": database_analysis.get("query_text_policy"),
            },
            model_metadata=self._last_model_metadata,
        )
