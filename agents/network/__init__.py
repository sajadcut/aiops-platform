from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

from agents.network.engine import build_network_reliability_analysis
from agents.shared.base import AgentInput, AgentOutput, OperationalHypothesis
from agents.shared.domain_agent import DomainDiagnosticAgent, DomainSpec
from agents.shared.intelligence import build_deterministic_analysis, sanitize_prompt_value
from domain.contracts.config import settings
from domain.contracts.logging import logger
from integrations.llm.base import LLMAdapter


class NetworkAgent(DomainDiagnosticAgent):
    spec = DomainSpec(
        name="network",
        description="Multi-layer Network Reliability Investigator with source-to-destination path localization",
        focus=[
            "L2/L3 interface state, errors/drops, routes, gateways and reachability",
            "L4 TCP connect, retransmission, resets, SYN failures, timeouts and listener/service relation",
            "DNS lookup success, NXDOMAIN, SERVFAIL, timeout, latency, resolver divergence and record mismatch",
            "L7 HTTP/TLS/service-to-service symptoms only when live evidence supports them",
            "bandwidth utilization, packet rate, queue/drop and conntrack pressure",
            "source-to-destination path correlation rather than destination-only diagnosis",
            "Kubernetes/eBPF flows, denied flows, service dependencies, DNS/HTTP/Kafka flows when supplied",
            "DNS, routing, firewall/policy, listener/service, packet loss, congestion, TLS/identity, application timeout and dependency outage separation",
        ],
        required_evidence_types=["metric"],
        read_tools=["prometheus_query", "zabbix_read", "vm_telemetry", "kubectl_get", "knowledge_search"],
        default_handoffs=["infrastructure", "application", "identity", "dependency", "security"],
    )

    def __init__(self, llm_adapter: Optional[LLMAdapter] = None):
        super().__init__(llm_adapter)

    @staticmethod
    def _network_hypothesis_context(
        item: Dict[str, Any],
        network_analysis: Dict[str, Any],
    ) -> Dict[str, Any]:
        ids = [str(value) for value in item.get("evidence_ids", []) if value not in (None, "")]
        contexts = network_analysis.get("evidence_path_context", {})
        matched = [contexts[eid] for eid in ids if isinstance(contexts, dict) and eid in contexts]

        def inferred(key: str, default: Any) -> Any:
            supplied = item.get(key)
            if supplied not in (None, ""):
                return supplied
            values = [row.get(key) for row in matched if row.get(key) not in (None, "", "unknown")]
            if not values:
                return default
            unique = list(dict.fromkeys(values))
            return unique[0] if len(unique) == 1 else "multiple"

        stamps = [row.get("timestamp") for row in matched if row.get("timestamp")]
        supplied_window = item.get("time_window")
        if isinstance(supplied_window, dict):
            time_window = supplied_window
        else:
            default_window = network_analysis.get("time_window", {})
            time_window = {
                "start": min(stamps) if stamps else default_window.get("start"),
                "end": max(stamps) if stamps else default_window.get("end"),
            }
        return {
            "hypothesis": str(item.get("hypothesis") or ""),
            "evidence_ids": ids,
            "source": inferred("source", "unknown"),
            "destination": inferred("destination", "unknown"),
            "protocol": inferred("protocol", "unknown"),
            "port": inferred("port", None),
            "time_window": time_window,
            "expected_falsification_result": str(
                item.get("expected_falsification_result")
                or "Repeat the same source-to-destination check and collect the layer-specific evidence expected to disprove this hypothesis."
            ),
        }

    async def analyze(self, input_data: AgentInput) -> AgentOutput:
        evidence = self.evidence_items(input_data)
        raw_evidence = input_data.context.get("evidence", []) if input_data.context else []
        deterministic_evidence = [
            item for item in raw_evidence
            if isinstance(item, dict) and not self.evidence_is_stale(item)
        ] if isinstance(raw_evidence, list) else []
        deterministic = build_deterministic_analysis(
            self.name,
            deterministic_evidence,
            required_types=self.spec.required_evidence_types,
            service_name=input_data.service_name,
        )
        network_context = dict(input_data.context or {})
        if input_data.time_range and "time_range" not in network_context:
            network_context["time_range"] = input_data.time_range
        network_analysis = build_network_reliability_analysis(
            deterministic_evidence,
            service_name=input_data.service_name,
            context=network_context,
        )
        prompt_evidence = self._prompt_evidence(evidence)
        evidence_ids = self.evidence_ids(input_data)
        auxiliary_full = self.auxiliary_context(input_data)
        auxiliary = self._bounded_prompt_value(auxiliary_full)
        peer_full = self._peer_context(input_data)
        peer_context = self._bounded_prompt_value(peer_full)
        missing = self.missing_evidence_for(input_data, self.spec.required_evidence_types)

        prompt = f"""You are the network specialist and a senior multi-layer Network Reliability Investigator in a production AIOps platform.
LIVE EVIDENCE is authoritative. RAG/Memory and PEER OPERATIONAL CONTEXT are auxiliary only. Never inherit peer confidence or causal conclusions. Never invent current state.
NETWORK_ANALYSIS is deterministic pre-LLM feature extraction across L2/L3, L4, DNS, L7, capacity, source-to-destination paths and Kubernetes/eBPF flows. Treat deterministic cause candidates as hypotheses requiring falsification, never automatic root-cause verdicts.
Critical causal rule: a connection timeout by itself is not proof of a network root cause. Localize the failing layer using the same source -> destination, protocol and port tuple.
Distinguish: DNS, routing, firewall/policy, listener/service, packet loss, congestion, TLS/identity, application timeout and dependency outage. A healthy destination host does not prove the source-to-destination path is healthy.
When Kubernetes/eBPF evidence exists, use flows, denied flows, service dependency, DNS request/response, HTTP failures and Kafka/network flow evidence. Do not invent flow state when it is absent.
For every hypothesis include: source, destination, protocol, port, time_window and expected_falsification_result in addition to the standard hypothesis fields. If any path field is unknown, explicitly use "unknown" rather than guessing.
Prefer direct read-only falsification using route/gateway, DNS, TCP connect, listener, policy/flow, retransmission/loss, TLS and L7 evidence for the same path tuple.
Focus areas: {json.dumps(self.spec.focus)}
Return one JSON object with keys: severity, health_status, findings, affected_components,
probable_dependencies, blast_radius, hypotheses, missing_evidence, handoff_agents,
immediate_checks, escalation_target, risk_level, uncertainty_reason, confidence.
Each hypothesis: hypothesis, probability, evidence_ids, conflicting_evidence_ids,
falsification_checks, impacted_components, recommended_next_evidence,
source, destination, protocol, port, time_window, expected_falsification_result.
Only cite LIVE EVIDENCE IDs. immediate_checks are read-only. Request missing factual state instead of guessing it.
Incident={input_data.incident_id}
Service={input_data.service_name}
Summary={input_data.evidence_summary}
NETWORK_ANALYSIS={json.dumps(sanitize_prompt_value(network_analysis), default=str)}
DETERMINISTIC_ANALYSIS={json.dumps(sanitize_prompt_value(deterministic), default=str)}
LIVE_EVIDENCE={json.dumps(prompt_evidence, default=str)}
AUXILIARY_CONTEXT={json.dumps(auxiliary, default=str)}
PEER_OPERATIONAL_CONTEXT={json.dumps(peer_context, default=str)}"""

        structured_failed = False
        try:
            result = await self.generate_structured(prompt)
        except Exception as exc:
            structured_failed = True
            logger.error(f"network structured analysis failed: {exc}")
            causal_codes = [
                str(row.get("code")) for row in network_analysis.get("cause_candidates", [])
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
                "missing_evidence": ["successful structured network analysis"],
                "handoff_agents": list(network_analysis.get("handoff_candidates") or self.spec.default_handoffs),
                "immediate_checks": ["Collect path-localized route, DNS, TCP/listener, policy/flow and packet-loss evidence"],
                "escalation_target": "network-operator",
                "risk_level": "low",
                "uncertainty_reason": "structured_analysis_failed",
                "confidence": 0.0,
            }

        all_missing = sorted(set(missing + self.normalize_list(result.get("missing_evidence"), 8)))
        hypotheses: List[OperationalHypothesis] = []
        hypothesis_contexts: List[Dict[str, Any]] = []
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
            hypothesis_contexts.append(self._network_hypothesis_context(item, network_analysis))

        confidence = self.safe_confidence(result.get("confidence"), len(evidence), all_missing, conflicts)
        findings = self.normalize_list(result.get("findings"), 10)
        if structured_failed and not findings:
            findings = [
                str(row.get("code")) for row in network_analysis.get("cause_candidates", [])
                if isinstance(row, dict) and row.get("code")
            ][:10]
        actions = self.normalize_list(result.get("immediate_checks"), settings.AGENT_MAX_RECOMMENDATIONS)
        coverage = self.evidence_coverage(len(evidence), all_missing)
        handoffs = self.normalize_list(result.get("handoff_agents"), 6)
        for target in network_analysis.get("handoff_candidates", []):
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
            finding_type="network_analysis",
            statement=("Network evidence: " + ("; ".join(findings) if findings else "no confirmed network-layer fault yet"))[:600],
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
            escalation_target=str(result.get("escalation_target") or "network-operator"),
            risk_level=str(result.get("risk_level", "low")).lower(),
            uncertainty_reason=str(result.get("uncertainty_reason") or ("missing_evidence" if all_missing else "")) or None,
            requires_human_review=self.human_review_required(confidence, all_missing),
            analysis_details={
                "focus": self.spec.focus,
                "network_analysis": network_analysis,
                "network_layers": network_analysis.get("layers", {}),
                "path_analysis": network_analysis.get("path_analysis", []),
                "network_hypotheses": network_analysis.get("network_hypotheses", []),
                "llm_network_hypotheses": hypothesis_contexts,
                "uncertain_observations": network_analysis.get("uncertain_observations", []),
                "evidence_gap_matrix": deterministic.get("evidence_gap_matrix", {}),
                "next_best_evidence": network_analysis.get("next_best_evidence", []),
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
                "causal_policy": network_analysis.get("policy"),
            },
            model_metadata=self._last_model_metadata,
        )
