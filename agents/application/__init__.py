import json
from typing import Any, Dict, List, Optional

from agents.application.engine import build_application_analysis
from agents.application.investigation import build_application_peer_context, build_trace_path_analysis
from agents.shared.base import AgentInput, AgentOutput, BaseAgent, OperationalHypothesis
from agents.shared.intelligence import build_deterministic_analysis, prompt_evidence_projection, sanitize_prompt_value
from domain.contracts.config import settings
from domain.contracts.logging import logger
from integrations.llm.base import LLMAdapter


class ApplicationAgent(BaseAgent):
    def __init__(self, llm_adapter: Optional[LLMAdapter] = None):
        super().__init__(llm_adapter)

    @property
    def name(self) -> str:
        return "application"

    @property
    def description(self) -> str:
        return "Application reliability investigation using deterministic RED, endpoint, trace, dependency, saturation and change evidence"

    @property
    def allowed_tools(self) -> List[str]:
        return ["zabbix_read", "elasticsearch_logs", "prometheus_query", "knowledge_search"]

    @staticmethod
    def _expected_observations(result: Dict[str, Any], evidence_ids: List[str]) -> List[Dict[str, Any]]:
        rows: List[Dict[str, Any]] = []
        for item in result.get("hypotheses", [])[: settings.AGENT_MAX_HYPOTHESES]:
            if not isinstance(item, dict) or not item.get("hypothesis"):
                continue
            observations = BaseAgent.normalize_list(
                item.get("expected_observations") or item.get("expected_observation"), 5
            )
            rows.append({
                "hypothesis": str(item.get("hypothesis")),
                "expected_observations": observations,
                "supporting_evidence_ids": [str(x) for x in item.get("evidence_ids", []) if str(x) in evidence_ids],
                "conflicting_evidence_ids": [str(x) for x in item.get("conflicting_evidence_ids", []) if str(x) in evidence_ids],
            })
        return rows

    async def analyze(self, input_data: AgentInput) -> AgentOutput:
        logger.info(f"ApplicationAgent analyzing: {input_data.incident_id}")
        evidence = self.evidence_items(input_data)
        prompt_evidence = prompt_evidence_projection(evidence, settings.AGENT_MAX_EVIDENCE_ITEMS)
        shared_deterministic = build_deterministic_analysis(
            "application", evidence, ["log", "metric"], input_data.service_name
        )
        application_analysis = build_application_analysis(
            evidence,
            service_name=input_data.service_name,
            context=(input_data.context.get("summary", {}) if isinstance(input_data.context.get("summary", {}), dict) else {}),
        )
        evidence_ids = self.evidence_ids(input_data)
        trace_path_analysis = build_trace_path_analysis(application_analysis.get("trace_analysis", {}))
        peer_application_context = build_application_peer_context(input_data.context or {}, evidence_ids)
        application_analysis["trace_path_analysis"] = trace_path_analysis
        auxiliary = self.auxiliary_context(input_data)
        prompt_auxiliary = sanitize_prompt_value(auxiliary)
        prompt_peer_context = sanitize_prompt_value(peer_application_context)
        logs = [item for item in evidence if str(item.get("type", "")).lower() == "log"]
        metrics = [item for item in evidence if str(item.get("type", "")).lower() == "metric"]
        traces = [item for item in evidence if str(item.get("type", "")).lower() == "trace"]
        missing = self.missing_evidence_for(input_data, ["log", "metric"])

        prompt = f"""You are a senior SRE application analyst and production Application Reliability Investigator. LIVE EVIDENCE is authoritative. Auxiliary Knowledge RAG and Operational Memory may suggest checks or historical patterns but are never proof of current state. Never invent deployments, dependencies, traces, versions, configuration changes, exceptions, metrics or executed actions.

APPLICATION_ANALYSIS is a deterministic feature extraction layer and must be used before free-form reasoning. It contains RED observations, p50/p90/p95/p99 latency evidence, endpoint/status-family impact, error signature clusters, exception/stack timing, resource pressure, parent/child trace path candidates, dependency signals, before-vs-incident baselines, change proximity, scope analysis and traffic-vs-regression classification. These are observations, not automatic root-cause verdicts.

PEER_APPLICATION_CONTEXT contains bounded Dependency/Database/Network/Change agent analysis published by orchestration. It is auxiliary analysis only. Never inherit a peer agent's confidence or causal conclusion. A peer Evidence ID overlap only confirms that the cited LIVE EVIDENCE item is visible here; independently verify what that evidence actually proves. Unverified peer findings may suggest checks but must not increase causal confidence or authorize an action.

Use RED and causal investigation:
- Request rate: identify spike/drop and compare against baseline when available.
- Error rate: distinguish 4xx/5xx, endpoint-specific failure and dominant error signatures.
- Duration: inspect p50/p90/p95/p99 and tail-latency divergence, not average latency alone.
- Distinguish timeout/reset/retry/retry-amplification, thread/worker saturation, connection-pool exhaustion, GC/memory/CPU pressure, FD/socket exhaustion and queue/backpressure.
- Separate health/readiness failures from business-endpoint failures.
- Use traces when available for slow spans, error spans, parent/child critical-path candidates and downstream contributors. Do not treat a single longest span as a complete critical path when parent/child structure disagrees or is incomplete.
- Assess SLO/error-budget burn, release/config/feature-flag timing, region/instance scope and partial-vs-broad outage.
- A deployment preceding an incident is correlation only. Require before/after delta, scope overlap or instance/canary contrast before raising regression confidence.
- A traffic spike is not a software regression unless error/latency/resource evidence supports it.
- Do not attribute a database/network/dependency-caused symptom to the application when stronger downstream evidence exists. In that case emit the appropriate handoff agent and explain the causal boundary.
- Use Dependency/Change peer findings to target investigation only after checking their cited LIVE EVIDENCE. Peer agreement is not a substitute for evidence.

For EVERY hypothesis return: supporting live evidence IDs, conflicting live evidence IDs, cheapest read-only falsification checks, expected_observations if the hypothesis is true, impacted components and recommended next evidence. A hypothesis without a falsification path should remain low confidence.

Return JSON keys: severity, health_status, findings, error_patterns, http_status_patterns, latency_signals, exception_clusters, endpoint_impacts, deployment_correlation, config_drift_signals, dependency_signals, probable_dependencies, affected_components, blast_radius, hypotheses, missing_evidence, handoff_agents, immediate_checks, escalation_target, risk_level, uncertainty_reason, confidence.
Each hypothesis: hypothesis, probability, evidence_ids, conflicting_evidence_ids, falsification_checks, expected_observations, impacted_components, recommended_next_evidence. Only LIVE EVIDENCE IDs may appear in evidence fields. Immediate checks are read-only. deploy/restart/rollback/scale/modify actions are recommendations only and must never be represented as read-only investigation.

Incident={input_data.incident_id}\nService={input_data.service_name}\nSummary={input_data.evidence_summary}\nAPPLICATION_ANALYSIS={json.dumps(sanitize_prompt_value(application_analysis), default=str)}\nSHARED_DETERMINISTIC_ANALYSIS={json.dumps(shared_deterministic, default=str)}\nLIVE_EVIDENCE={json.dumps(prompt_evidence, default=str)}\nAUXILIARY_CONTEXT={json.dumps(prompt_auxiliary, default=str)}\nPEER_APPLICATION_CONTEXT={json.dumps(prompt_peer_context, default=str)}\nContextSummary={json.dumps(sanitize_prompt_value(input_data.context.get('summary', {})), default=str)}"""
        try:
            result = await self.generate_structured(prompt)
        except Exception as exc:
            logger.error(f"ApplicationAgent analysis failed: {exc}")
            result = {
                "severity": "unknown",
                "health_status": "unknown",
                "findings": [],
                "error_patterns": [],
                "affected_components": [],
                "blast_radius": "unknown",
                "hypotheses": [],
                "handoff_agents": ["triage"],
                "immediate_checks": ["Collect application logs and service metrics"],
                "uncertainty_reason": "structured_analysis_failed",
                "confidence": 0.0,
            }
            missing = sorted(set(missing + ["successful structured application analysis"]))

        all_missing = sorted(set(missing + self.normalize_list(result.get("missing_evidence"), 8)))
        hypotheses = []
        conflict_count = len(application_analysis.get("conflicts", []))
        for item in result.get("hypotheses", [])[: settings.AGENT_MAX_HYPOTHESES]:
            if isinstance(item, dict) and item.get("hypothesis"):
                conflicts = [str(x) for x in item.get("conflicting_evidence_ids", []) if str(x) in evidence_ids]
                conflict_count += len(conflicts)
                falsification = self.normalize_list(item.get("falsification_checks"), 5)
                expected = self.normalize_list(item.get("expected_observations") or item.get("expected_observation"), 5)
                if expected:
                    falsification = (falsification + [f"Expected if true: {value}" for value in expected])[:8]
                hypotheses.append(OperationalHypothesis(
                    hypothesis=str(item["hypothesis"]),
                    probability=self.safe_confidence(item.get("probability", 0), len(evidence), all_missing, len(conflicts)),
                    evidence_ids=[str(x) for x in item.get("evidence_ids", []) if str(x) in evidence_ids],
                    conflicting_evidence_ids=conflicts,
                    falsification_checks=falsification,
                    impacted_components=self.normalize_list(item.get("impacted_components"), 6),
                    recommended_next_evidence=self.normalize_list(item.get("recommended_next_evidence"), 6),
                ))

        confidence = self.safe_confidence(result.get("confidence"), len(evidence), all_missing, conflict_count)
        actions = self.normalize_list(result.get("immediate_checks"), settings.AGENT_MAX_RECOMMENDATIONS)
        patterns = self.normalize_list(result.get("error_patterns"), 6)
        findings = self.normalize_list(result.get("findings"), 10) or patterns
        handoffs = self.normalize_list(result.get("handoff_agents"), 6)

        for candidate in application_analysis.get("dependency_analysis", {}).get("handoff_candidates", []):
            if not isinstance(candidate, dict):
                continue
            target = str(candidate.get("agent") or "")
            if target and target != self.name and target not in handoffs and len(handoffs) < 6:
                handoffs.append(target)
        for candidate in peer_application_context.get("linked_handoff_candidates", []):
            if not isinstance(candidate, dict):
                continue
            target = str(candidate.get("agent") or "")
            if target and target != self.name and target not in handoffs and len(handoffs) < 6:
                handoffs.append(target)
        for hint in shared_deterministic.get("suggested_handoffs", []):
            target = str(hint.get("agent", "")) if isinstance(hint, dict) else ""
            if target and target != self.name and target not in handoffs and len(handoffs) < 6:
                handoffs.append(target)

        downstream_handoffs = [
            row for row in application_analysis.get("dependency_analysis", {}).get("handoff_candidates", [])
            if isinstance(row, dict) and row.get("agent") in {"database", "network", "dependency"}
        ]
        peer_downstream_handoffs = [
            row for row in peer_application_context.get("linked_handoff_candidates", [])
            if isinstance(row, dict) and row.get("agent") in {"database", "network", "dependency"}
        ]
        if downstream_handoffs or peer_downstream_handoffs:
            findings.append("Stronger or independently corroborated downstream evidence exists; application symptoms must not be treated as application root cause without falsifying the downstream path")

        if not actions:
            actions = [
                f"Collect {row.get('evidence')} because {row.get('reason')}"
                for row in application_analysis.get("next_best_evidence", [])
                if isinstance(row, dict) and row.get("evidence")
            ][: settings.AGENT_MAX_RECOMMENDATIONS]

        statement = "Application evidence indicates " + (
            "; ".join(findings) if findings else "no confirmed application fault pattern yet"
        )
        return AgentOutput(
            agent_name=self.name,
            finding_type="application_analysis",
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
            probable_dependencies=self.normalize_list(result.get("probable_dependencies") or result.get("dependency_signals"), 8),
            affected_components=self.normalize_list(result.get("affected_components"), 8),
            blast_radius=str(result.get("blast_radius", application_analysis.get("scope_analysis", {}).get("outage_scope", "unknown"))),
            escalation_target=str(result.get("escalation_target") or "application-sre"),
            risk_level=str(result.get("risk_level", "low")).lower(),
            uncertainty_reason=str(result.get("uncertainty_reason") or ("missing_evidence" if all_missing else "")) or None,
            requires_human_review=self.human_review_required(confidence, all_missing),
            analysis_details={
                "red_features": application_analysis.get("red_features", {}),
                "latency_percentiles": application_analysis.get("latency_percentiles", {}),
                "tail_latency_present": application_analysis.get("tail_latency_present", False),
                "http_status_patterns": application_analysis.get("http", {}).get("status_families", {}),
                "endpoint_impacts": application_analysis.get("http", {}).get("endpoint_impacts", []),
                "health_vs_business": application_analysis.get("http", {}).get("health_vs_business"),
                "error_patterns": patterns,
                "error_signature_clusters": application_analysis.get("error_signature_clusters", []),
                "exception_clusters": result.get("exception_clusters", []),
                "resource_pressure": application_analysis.get("resource_pressure", {}),
                "resource_keyword_signals": application_analysis.get("resource_keyword_signals", {}),
                "retry_metrics": application_analysis.get("retry_metrics", []),
                "slo_signals": application_analysis.get("slo_signals", []),
                "trace_analysis": application_analysis.get("trace_analysis", {}),
                "trace_path_analysis": trace_path_analysis,
                "dependency_analysis": application_analysis.get("dependency_analysis", {}),
                "peer_application_context": peer_application_context,
                "peer_dependency_finding_count": len(peer_application_context.get("dependency_findings", [])),
                "peer_change_finding_count": len(peer_application_context.get("change_findings", [])),
                "deployment_correlation": result.get("deployment_correlation") or application_analysis.get("change_analysis", {}),
                "config_drift_signals": result.get("config_drift_signals", []),
                "traffic_vs_regression": application_analysis.get("traffic_vs_regression", {}),
                "scope_analysis": application_analysis.get("scope_analysis", {}),
                "baseline_deltas": application_analysis.get("baseline_deltas", []),
                "deterministic_conflicts": application_analysis.get("conflicts", []),
                "evidence_gaps": application_analysis.get("evidence_gaps", []),
                "next_best_evidence": application_analysis.get("next_best_evidence", []),
                "hypothesis_expected_observations": self._expected_observations(result, evidence_ids),
                "shared_deterministic_analysis": shared_deterministic,
                "application_deterministic_analysis": application_analysis,
                "log_evidence_count": len(logs),
                "metric_evidence_count": len(metrics),
                "trace_evidence_count": len(traces),
                "knowledge_context_count": len(auxiliary["knowledge_rag"]),
                "memory_context_count": len(auxiliary["operational_memory"]),
                "conflicting_evidence_count": conflict_count,
                "execution_boundary": "analysis_only",
            },
            model_metadata=self._last_model_metadata,
        )