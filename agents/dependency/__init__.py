from __future__ import annotations

import json
from typing import List, Optional

from agents.dependency.engine import build_dependency_causal_analysis
from agents.shared.base import AgentInput, AgentOutput, OperationalHypothesis
from agents.shared.domain_agent import DomainDiagnosticAgent, DomainSpec
from agents.shared.intelligence import build_deterministic_analysis, sanitize_prompt_value
from domain.contracts.config import settings
from domain.contracts.logging import logger
from integrations.llm.base import LLMAdapter


class DependencyAgent(DomainDiagnosticAgent):
    spec = DomainSpec(
        name="dependency",
        description="Service Topology & Causal Dependency Investigator with directed graph and failure-propagation analysis",
        focus=[
            "directed caller-to-callee service topology with per-edge rate/error/latency/timeout/retry windows",
            "first failing edge, earliest anomaly and temporal failure propagation",
            "upstream/downstream health, fan-out, shared dependencies and critical paths",
            "cascading failure, retry amplification, timeout propagation and circuit breakers",
            "external SaaS/API, database, messaging, identity and regional dependencies",
            "dependency version/change correlation without treating proximity as causality",
            "root contributor scoring from edge timing, downstream health, retries, shared-node effects and propagation direction",
            "unknown or uninstrumented virtual nodes without treating missing graph segments as dependency absence",
            "metrics/logs/topology fallback for incomplete traces with explicit confidence reduction",
        ],
        required_evidence_types=[],
        read_tools=["prometheus_query", "elasticsearch_logs", "zabbix_read", "knowledge_search"],
        default_handoffs=["application", "database", "network", "identity", "messaging"],
    )

    def __init__(self, llm_adapter: Optional[LLMAdapter] = None):
        super().__init__(llm_adapter)

    async def analyze(self, input_data: AgentInput) -> AgentOutput:
        evidence = self.evidence_items(input_data)
        prompt_evidence = self._prompt_evidence(evidence)
        deterministic = build_deterministic_analysis(
            self.name,
            evidence,
            required_types=self.spec.required_evidence_types,
            service_name=input_data.service_name,
        )
        dependency_analysis = build_dependency_causal_analysis(
            evidence,
            service_name=input_data.service_name,
            context=input_data.context or {},
        )
        evidence_ids = self.evidence_ids(input_data)
        auxiliary_full = self.auxiliary_context(input_data)
        auxiliary = self._bounded_prompt_value(auxiliary_full)
        peer_full = self._peer_context(input_data)
        peer_context = self._bounded_prompt_value(peer_full)

        engine_missing = [
            str(row.get("evidence"))
            for row in dependency_analysis.get("next_best_evidence", [])
            if isinstance(row, dict) and row.get("evidence")
        ][:5]
        missing = sorted(set(self.missing_evidence_for(input_data, self.spec.required_evidence_types) + engine_missing))
        confidence_ceiling = float(dependency_analysis.get("confidence_ceiling", 0.55) or 0.55)

        prompt = f"""You are the dependency specialist and a senior Service Topology & Causal Dependency Investigator in a production AIOps platform.
LIVE EVIDENCE is authoritative. RAG/Memory and PEER OPERATIONAL CONTEXT are auxiliary only. Never inherit peer confidence and never use historical similarity as proof of current dependency health.
DEPENDENCY_CAUSAL_ANALYSIS is deterministic pre-LLM analysis. Preserve its directed caller->callee topology, edge time windows, virtual unknown nodes and temporal ordering. Re-check causal interpretation against LIVE EVIDENCE, but do not invent missing nodes or remove unknown/uninstrumented nodes.
A service producing the most error logs is NOT automatically the root cause. Root contributor reasoning must account for first failing edge, earliest anomaly, downstream health, upstream retry amplification, shared-node effect, error propagation direction and conflicting/deeper-downstream evidence.
For each edge consider caller, callee, request rate, error rate, latency, timeout, retry and time window. Analyze fan-out, shared dependencies, critical paths, cascading failure, retry amplification, timeout propagation, circuit breaker state, external API/SaaS, database, messaging, identity, region and dependency version/change evidence.
If traces are incomplete, metrics/logs/topology may fill observable gaps, but uncertainty must increase. Never interpret absence from an incomplete graph as proof that no dependency exists.
DETERMINISTIC confidence ceiling={confidence_ceiling}. Do not return confidence or hypothesis probability above this ceiling merely because a narrative seems plausible.
Focus areas: {json.dumps(self.spec.focus)}
Return one JSON object with keys: severity, health_status, findings, affected_components,
probable_dependencies, blast_radius, hypotheses, missing_evidence, handoff_agents,
immediate_checks, escalation_target, risk_level, uncertainty_reason, confidence.
Each hypothesis: hypothesis, probability, evidence_ids, conflicting_evidence_ids,
falsification_checks, impacted_components, recommended_next_evidence.
Only cite LIVE EVIDENCE IDs. immediate_checks are read-only. Describe root causes only as causal contributor candidates requiring falsification unless independent evidence proves more.
Incident={input_data.incident_id}
Service={input_data.service_name}
Summary={input_data.evidence_summary}
DEPENDENCY_CAUSAL_ANALYSIS={json.dumps(sanitize_prompt_value(dependency_analysis), default=str)}
DETERMINISTIC_ANALYSIS={json.dumps(sanitize_prompt_value(deterministic), default=str)}
LIVE_EVIDENCE={json.dumps(prompt_evidence, default=str)}
AUXILIARY_CONTEXT={json.dumps(auxiliary, default=str)}
PEER_OPERATIONAL_CONTEXT={json.dumps(peer_context, default=str)}"""

        structured_failed = False
        try:
            result = await self.generate_structured(prompt)
        except Exception as exc:
            structured_failed = True
            logger.error(f"dependency structured analysis failed: {exc}")
            top_roots = dependency_analysis.get("root_contributors", [])
            findings = []
            if top_roots:
                root = top_roots[0]
                findings.append(
                    f"causal dependency contributor candidate {root.get('edge_id')} score={root.get('root_contributor_score')}"
                )
            result = {
                "severity": "unknown",
                "health_status": "unknown",
                "findings": findings,
                "affected_components": [input_data.service_name] if input_data.service_name else [],
                "probable_dependencies": [str(row.get("callee")) for row in top_roots[:5] if isinstance(row, dict) and row.get("callee")],
                "blast_radius": "unknown",
                "hypotheses": [],
                "missing_evidence": ["successful structured dependency synthesis"],
                "handoff_agents": [],
                "immediate_checks": ["Inspect the first failing edge and compare direct downstream health with upstream retry and timeout propagation"],
                "escalation_target": "dependency-operator",
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
            conflicting = [str(value) for value in item.get("conflicting_evidence_ids", []) if str(value) in evidence_ids]
            conflicts += len(conflicting)
            probability = self.safe_confidence(item.get("probability", 0), len(evidence), all_missing, len(conflicting))
            probability = min(probability, confidence_ceiling)
            hypotheses.append(OperationalHypothesis(
                hypothesis=str(item["hypothesis"]),
                probability=probability,
                evidence_ids=[str(value) for value in item.get("evidence_ids", []) if str(value) in evidence_ids],
                conflicting_evidence_ids=conflicting,
                falsification_checks=self.normalize_list(item.get("falsification_checks"), 5),
                impacted_components=self.normalize_list(item.get("impacted_components"), 6),
                recommended_next_evidence=self.normalize_list(item.get("recommended_next_evidence"), 6),
            ))

        confidence = self.safe_confidence(result.get("confidence"), len(evidence), all_missing, conflicts)
        confidence = min(confidence, confidence_ceiling)
        findings = self.normalize_list(result.get("findings"), 10)
        actions = self.normalize_list(result.get("immediate_checks"), settings.AGENT_MAX_RECOMMENDATIONS)
        coverage = self.evidence_coverage(len(evidence), all_missing)
        handoffs = self.normalize_list(result.get("handoff_agents"), 6)
        for hint in dependency_analysis.get("suggested_handoffs", []):
            target = str(hint.get("agent", "")) if isinstance(hint, dict) else ""
            if target and target != self.name and target not in handoffs and len(handoffs) < 6:
                handoffs.append(target)
        for hint in deterministic.get("suggested_handoffs", []):
            target = str(hint.get("agent", "")) if isinstance(hint, dict) else ""
            if target and target != self.name and target not in handoffs and len(handoffs) < 6:
                handoffs.append(target)
        if not handoffs:
            handoffs = list(self.spec.default_handoffs)

        probable_dependencies = self.normalize_list(result.get("probable_dependencies"), 8)
        for root in dependency_analysis.get("root_contributors", [])[:8]:
            callee = str(root.get("callee", "")) if isinstance(root, dict) else ""
            if callee and callee not in probable_dependencies and len(probable_dependencies) < 8:
                probable_dependencies.append(callee)

        uncertainty = str(result.get("uncertainty_reason") or "")
        if dependency_analysis.get("uncertainty_level") in {"medium", "high"}:
            deterministic_reason = f"{dependency_analysis.get('uncertainty_level')}_dependency_graph_uncertainty_due_to_trace_completeness"
            uncertainty = deterministic_reason if not uncertainty else f"{uncertainty}; {deterministic_reason}"

        return AgentOutput(
            agent_name=self.name,
            finding_type="dependency_causal_analysis",
            statement=("Dependency evidence: " + ("; ".join(findings) if findings else "no causally supported dependency root contributor yet"))[:600],
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
            probable_dependencies=probable_dependencies,
            affected_components=self.normalize_list(result.get("affected_components"), 8),
            blast_radius=str(result.get("blast_radius", "unknown")),
            escalation_target=str(result.get("escalation_target") or "dependency-operator"),
            risk_level=str(result.get("risk_level", "low")).lower(),
            uncertainty_reason=uncertainty or None,
            requires_human_review=self.human_review_required(
                confidence,
                all_missing,
                severe=dependency_analysis.get("uncertainty_level") == "high",
            ),
            analysis_details={
                "focus": self.spec.focus,
                "dependency_analysis": dependency_analysis,
                "dependency_graph": dependency_analysis.get("dependency_graph", {}),
                "edge_health": dependency_analysis.get("edge_health", []),
                "first_failing_edge": dependency_analysis.get("first_failing_edge"),
                "earliest_anomaly": dependency_analysis.get("earliest_anomaly"),
                "propagation_timeline": dependency_analysis.get("propagation_timeline", []),
                "root_contributors": dependency_analysis.get("root_contributors", []),
                "root_contributor_score": dependency_analysis.get("root_contributor_score", 0.0),
                "fan_out": dependency_analysis.get("fan_out", []),
                "shared_dependencies": dependency_analysis.get("shared_dependencies", []),
                "critical_path_candidates": dependency_analysis.get("critical_path_candidates", []),
                "cascading_failures": dependency_analysis.get("cascading_failures", []),
                "retry_amplification": dependency_analysis.get("retry_amplification", []),
                "timeout_propagation": dependency_analysis.get("timeout_propagation", []),
                "circuit_breakers": dependency_analysis.get("circuit_breakers", []),
                "dependency_inventory": dependency_analysis.get("dependency_inventory", {}),
                "trace_completeness": dependency_analysis.get("trace_completeness", {}),
                "uncertainty_level": dependency_analysis.get("uncertainty_level"),
                "confidence_ceiling": confidence_ceiling,
                "next_best_evidence": dependency_analysis.get("next_best_evidence", []),
                "deterministic_analysis": deterministic,
                "shared_deterministic_analysis": deterministic,
                "knowledge_context_count": len(auxiliary_full["knowledge_rag"]),
                "memory_context_count": len(auxiliary_full["operational_memory"]),
                "peer_finding_count": len(peer_full["findings"]),
                "peer_disagreement": bool(peer_full["coordination"].get("disagreement")),
                "conflicting_evidence_count": conflicts,
                "prompt_evidence_count": len(prompt_evidence),
                "structured_analysis_failed": structured_failed,
                "execution_boundary": "analysis_only",
                "causal_policy": dependency_analysis.get("policy"),
            },
            model_metadata=self._last_model_metadata,
        )
