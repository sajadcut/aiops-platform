import json
from typing import List, Optional

from agents.shared.base import AgentInput, AgentOutput, BaseAgent, OperationalHypothesis
from agents.shared.intelligence import build_deterministic_analysis, prompt_evidence_projection, sanitize_prompt_value
from domain.contracts.config import settings
from domain.contracts.logging import logger
from integrations.llm.base import LLMAdapter


class KubernetesAgent(BaseAgent):
    def __init__(self, llm_adapter: Optional[LLMAdapter] = None):
        super().__init__(llm_adapter)

    @property
    def name(self) -> str:
        return "kubernetes"

    @property
    def description(self) -> str:
        return "Kubernetes diagnostics: workload health, rollout, scheduling, networking, resources and events"

    @property
    def allowed_tools(self) -> List[str]:
        return ["kubectl_get", "kubectl_describe", "kubectl_logs", "prometheus_query", "knowledge_search"]

    async def analyze(self, input_data: AgentInput) -> AgentOutput:
        logger.info(f"KubernetesAgent analyzing: {input_data.incident_id}")
        evidence = self.evidence_items(input_data)
        prompt_evidence = prompt_evidence_projection(evidence, settings.AGENT_MAX_EVIDENCE_ITEMS)
        deterministic = build_deterministic_analysis("kubernetes", evidence, ["log", "metric"], input_data.service_name)
        evidence_ids = self.evidence_ids(input_data)
        auxiliary = self.auxiliary_context(input_data)
        logs = [item for item in evidence if str(item.get("type", "")).lower() == "log"]
        metrics = [item for item in evidence if str(item.get("type", "")).lower() == "metric"]
        events = [item for item in evidence if str(item.get("type", "")).lower() in {"event", "alert"}]
        missing = self.missing_evidence_for(input_data, ["log", "metric"])
        prompt = f"""You are a Kubernetes SRE and senior production reliability investigator. LIVE EVIDENCE is authoritative. Knowledge RAG and Operational Memory are auxiliary only. Do not claim pod states, rollout failures, OOMKills, scheduling failures, probe failures, storage failures or network faults unless evidenced.
Investigate the workload as a causal chain: Service/Ingress -> Endpoint/EndpointSlice -> Pod -> ReplicaSet/Deployment/StatefulSet/DaemonSet/Job -> Node -> Storage/Network. Inspect any available Pod/controller generation and availability, scheduling reasons and resource insufficiency, affinity/taints, image pulls, CrashLoopBackOff/restart trend/exit code/OOMKilled, readiness/liveness/startup probes, rollout state, admission webhooks, PVC/PV attach/mount, node pressure/eviction, HPA behavior, requests/limits/throttling, PDB constraints, Service endpoints, Ingress backends, DNS/service discovery, NetworkPolicy and event chronology. Compare resource configuration to historical metrics when the evidence provides both.
DETERMINISTIC_ANALYSIS provides bounded resource-evidence counts, timeline, metric deltas, gaps and handoff hints. It is not a diagnosis. Correlate Kubernetes events with log/metric time ordering and distinguish workload symptoms from node, storage, network, change or dependency causes.
Return JSON keys: severity, health_status, findings, workload_signals, rollout_signals, scheduling_signals, network_signals, resource_signals, probable_dependencies, affected_components, blast_radius, hypotheses, missing_evidence, handoff_agents, immediate_checks, escalation_target, risk_level, uncertainty_reason, confidence.
Hypotheses: hypothesis, probability, evidence_ids, conflicting_evidence_ids, falsification_checks, impacted_components, recommended_next_evidence. Only live evidence IDs may be cited. immediate_checks must be read-only kubectl/metrics/log inspection. Never execute apply/delete/rollout restart/scale.
Incident={input_data.incident_id}\nService={input_data.service_name}\nSummary={input_data.evidence_summary}\nDETERMINISTIC_ANALYSIS={json.dumps(deterministic, default=str)}\nLIVE_EVIDENCE={json.dumps(prompt_evidence, default=str)}\nAUXILIARY_CONTEXT={json.dumps(sanitize_prompt_value(auxiliary), default=str)}\nContextSummary={json.dumps(sanitize_prompt_value(input_data.context.get('summary', {})), default=str)}"""
        try:
            result = await self.generate_structured(prompt)
        except Exception as exc:
            logger.error(f"KubernetesAgent analysis failed: {exc}")
            result = {"severity":"unknown","health_status":"unknown","findings":[],"workload_signals":[],"affected_components":[],"blast_radius":"unknown","hypotheses":[],"handoff_agents":["infrastructure"],"immediate_checks":["Inspect workload status, events and recent logs"],"uncertainty_reason":"structured_analysis_failed","confidence":0.0}
            missing = sorted(set(missing + ["successful structured kubernetes analysis"]))

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
        actions = self.normalize_list(result.get("immediate_checks"), settings.AGENT_MAX_RECOMMENDATIONS)
        workload = self.normalize_list(result.get("workload_signals"), 6)
        findings = self.normalize_list(result.get("findings"), 10) or workload
        handoffs = self.normalize_list(result.get("handoff_agents"), 6)
        for hint in deterministic.get("suggested_handoffs", []):
            target = str(hint.get("agent", "")) if isinstance(hint, dict) else ""
            if target and target != self.name and target not in handoffs and len(handoffs) < 6:
                handoffs.append(target)
        statement = "Kubernetes evidence indicates " + ("; ".join(findings) if findings else "no confirmed workload failure yet")
        return AgentOutput(
            agent_name=self.name,
            finding_type="kubernetes_analysis",
            statement=statement[:600],
            severity=str(result.get("severity", "unknown")).lower(),
            health_status=str(result.get("health_status", "unknown")).lower(),
            confidence=confidence,
            evidence_ids=evidence_ids,
            evidence_count=len(evidence),
            evidence_coverage=self.evidence_coverage(len(evidence), all_missing),
            findings=findings,
            recommendations=actions,
            recommended_actions=self.analysis_only_actions(actions, suggested_tool="kubectl_get"),
            hypotheses=hypotheses,
            missing_evidence=all_missing,
            handoff_agents=handoffs,
            probable_dependencies=self.normalize_list(result.get("probable_dependencies"), 8),
            affected_components=self.normalize_list(result.get("affected_components"), 8),
            blast_radius=str(result.get("blast_radius", "unknown")),
            escalation_target=str(result.get("escalation_target") or "platform-sre"),
            risk_level=str(result.get("risk_level", "low")).lower(),
            uncertainty_reason=str(result.get("uncertainty_reason") or ("missing_evidence" if all_missing else "")) or None,
            requires_human_review=self.human_review_required(confidence, all_missing),
            analysis_details={
                "workload_signals": workload,
                "rollout_signals": result.get("rollout_signals", []),
                "scheduling_signals": result.get("scheduling_signals", []),
                "network_signals": result.get("network_signals", []),
                "resource_signals": result.get("resource_signals", []),
                "resource_evidence_counts": deterministic.get("resource_evidence_counts", {}),
                "deterministic_analysis": deterministic,
                "next_best_evidence": deterministic.get("next_best_evidence", []),
                "log_evidence_count": len(logs),
                "metric_evidence_count": len(metrics),
                "event_evidence_count": len(events),
                "knowledge_context_count": len(auxiliary["knowledge_rag"]),
                "memory_context_count": len(auxiliary["operational_memory"]),
                "conflicting_evidence_count": conflict_count,
            },
            model_metadata=self._last_model_metadata,
        )
