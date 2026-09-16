from __future__ import annotations

import json
import time
from typing import List, Optional

from agents.messaging.engine import build_messaging_reliability_analysis
from agents.shared.base import AgentInput, AgentOutput, OperationalHypothesis
from agents.shared.domain_agent import DomainDiagnosticAgent, DomainSpec
from agents.shared.intelligence import build_deterministic_analysis, sanitize_prompt_value
from domain.contracts.config import settings
from domain.contracts.logging import logger
from integrations.llm.base import LLMAdapter


class MessagingAgent(DomainDiagnosticAgent):
    spec = DomainSpec(
        name="messaging",
        description="Kafka/RabbitMQ and queue/event-driven Messaging Reliability Investigator",
        focus=[
            "broker reachability/failure, controller/leader, replication and broker disk/network pressure",
            "consumer lag level, derivative, message age and rebalance frequency",
            "Kafka under-replicated/offline partitions, ISR changes, leader imbalance and hot partitions",
            "queue depth trend, publish/consume/ack rates, unacked, retry, DLQ, redelivery and oldest message age",
            "broker failure versus slow/crashed consumer, producer surge, poison retry loop, network/storage pressure, partition skew and downstream failure",
            "queue depth alone never proves broker failure; trend and temporal corroboration are required",
        ],
        required_evidence_types=[],
        read_tools=["prometheus_query", "elasticsearch_logs", "zabbix_read", "knowledge_search"],
        default_handoffs=["application", "dependency", "network", "infrastructure"],
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
        messaging = build_messaging_reliability_analysis(
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
            for row in messaging.get("next_best_evidence", [])
            if isinstance(row, dict) and row.get("evidence")
        ][: settings.AGENT_MAX_DYNAMIC_EVIDENCE_TYPES]
        missing = sorted(set(self.missing_evidence_for(input_data, []) + engine_missing))
        ceiling = float(messaging.get("confidence_ceiling", 0.68) or 0.68)

        prompt = f"""You are the Messaging Reliability Investigator for Kafka, RabbitMQ and queue/event-driven systems.
LIVE EVIDENCE is authoritative. MESSAGING_RELIABILITY_ANALYSIS is deterministic pre-LLM analysis and must be evaluated before narrative synthesis.
Queue depth or a single consumer-lag snapshot never proves broker failure. Prefer lag/backlog trend and derivative, temporal ordering and cross-layer corroboration.
Separate broker failure, slow consumer, crashed consumer, producer surge, poison-message/retry loop, network problem, storage pressure, partition skew and downstream application failure.
Preserve supporting and conflicting evidence and use falsification-first hypotheses. If broker evidence is healthy while backlog is transient and draining, do not label the broker failed.
For Kafka consider consumer lag/growth, message age, under-replicated/offline partitions, leader imbalance, ISR changes, producer/consumer errors, rebalances, hot partitions and throughput skew.
For queue systems consider depth, publish/consume/ack rates, ack latency, unacked, retries, DLQ growth, redelivery and oldest message age.
Cross-check Application, Dependency, Network and Infrastructure contexts when deterministic handoffs request them.
DETERMINISTIC confidence ceiling={ceiling}. Do not exceed it.
Return one JSON object with keys: severity, health_status, findings, affected_components, probable_dependencies, blast_radius, hypotheses, missing_evidence, handoff_agents, immediate_checks, escalation_target, risk_level, uncertainty_reason, confidence.
Each hypothesis: hypothesis, probability, evidence_ids, conflicting_evidence_ids, falsification_checks, impacted_components, recommended_next_evidence.
Only cite LIVE EVIDENCE IDs. immediate_checks are read-only. Never execute broker/queue mutations.
Incident={input_data.incident_id}
Service={input_data.service_name}
Summary={input_data.evidence_summary}
MESSAGING_RELIABILITY_ANALYSIS={json.dumps(sanitize_prompt_value(messaging), default=str)}
DETERMINISTIC_ANALYSIS={json.dumps(sanitize_prompt_value(deterministic), default=str)}
LIVE_EVIDENCE={json.dumps(prompt_evidence, default=str)}
AUXILIARY_CONTEXT={json.dumps(auxiliary, default=str)}
PEER_OPERATIONAL_CONTEXT={json.dumps(peer_context, default=str)}"""

        structured_failed = False
        try:
            result = await self.generate_structured(prompt)
        except Exception as exc:
            structured_failed = True
            logger.error(f"messaging structured analysis failed: {exc}")
            result = {
                "severity": "unknown", "health_status": "unknown",
                "findings": [], "affected_components": [], "probable_dependencies": [],
                "blast_radius": "unknown", "hypotheses": [],
                "missing_evidence": ["successful structured messaging synthesis"],
                "handoff_agents": [], "immediate_checks": ["Inspect broker reachability and lag/backlog trends"],
                "escalation_target": "messaging-operator", "risk_level": "low",
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
        for hint in [*messaging.get("suggested_handoffs", []), *deterministic.get("suggested_handoffs", [])]:
            target = str(hint.get("agent", "")) if isinstance(hint, dict) else ""
            if target and target != self.name and target not in handoffs and len(handoffs) < 6:
                handoffs.append(target)
        if not handoffs:
            handoffs = list(self.spec.default_handoffs)

        uncertainty = str(result.get("uncertainty_reason") or "")
        if ceiling < 0.8:
            reason = "bounded_messaging_confidence_due_to_missing_trend_or_cross_source_evidence"
            uncertainty = reason if not uncertainty else f"{uncertainty}; {reason}"

        return AgentOutput(
            agent_name=self.name,
            finding_type="messaging_reliability_analysis",
            statement=("Messaging evidence: " + ("; ".join(findings) if findings else "no causally supported messaging failure yet"))[:600],
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
            escalation_target=str(result.get("escalation_target") or "messaging-operator"),
            risk_level=str(result.get("risk_level", "low")).lower(),
            uncertainty_reason=uncertainty or None,
            requires_human_review=self.human_review_required(confidence, all_missing),
            analysis_details={
                "focus": self.spec.focus,
                "messaging_analysis": messaging,
                "broker": messaging.get("broker", {}),
                "kafka": messaging.get("kafka", {}),
                "queue_systems": messaging.get("queue_systems", {}),
                "lag_trends": messaging.get("lag_trends", []),
                "cause_candidates": messaging.get("cause_candidates", []),
                "healthy_backlog_assessment": messaging.get("healthy_backlog_assessment", {}),
                "confidence_ceiling": ceiling,
                "deterministic_analysis": deterministic,
                "shared_deterministic_analysis": deterministic,
                "next_best_evidence": messaging.get("next_best_evidence", []),
                "stale_evidence_ids": self.stale_evidence_ids(input_data),
                "analyzer_telemetry": {
                    "analyzer": "messaging_reliability",
                    "duration_ms": analyzer_ms,
                    "evidence_count": len(evidence),
                    "source_count": len(messaging.get("source_counts", {})),
                },
                "knowledge_context_count": len(auxiliary_full["knowledge_rag"]),
                "memory_context_count": len(auxiliary_full["operational_memory"]),
                "peer_finding_count": len(peer_full["findings"]),
                "peer_disagreement": bool(peer_full["coordination"].get("disagreement")),
                "conflicting_evidence_count": conflicts,
                "prompt_evidence_count": len(prompt_evidence),
                "structured_analysis_failed": structured_failed,
                "execution_boundary": "analysis_only",
                "causal_policy": messaging.get("policy"),
            },
            model_metadata=self._last_model_metadata,
        )
