from __future__ import annotations

import json
from typing import List, Optional

from agents.change.engine import build_change_correlation_analysis
from agents.shared.base import AgentInput, AgentOutput, OperationalHypothesis
from agents.shared.domain_agent import DomainDiagnosticAgent, DomainSpec
from agents.shared.intelligence import build_deterministic_analysis, sanitize_prompt_value
from domain.contracts.config import settings
from domain.contracts.logging import logger
from integrations.llm.base import LLMAdapter


class ChangeAgent(DomainDiagnosticAgent):
    spec = DomainSpec(
        name="change",
        description="Change Intelligence / Regression Correlation Engine for evidence-based causal analysis of operational changes",
        focus=[
            "deployment/release/version/image-digest timeline",
            "configuration, environment/config hash, feature-flag and dependency-version changes",
            "infrastructure, Jenkins/build/deploy and Kubernetes rollout evidence",
            "replica transitions, release-caused restarts, schema/migration and simultaneous changes",
            "before-versus-after error/latency/traffic/resource/dependency/SLO deltas",
            "affected-scope overlap and endpoint/instance impact",
            "reproducibility and new/canary versus stable comparison",
            "alternative explanations and conflicting evidence",
            "rollback-candidate evidence without direct rollback authority",
        ],
        required_evidence_types=["log"],
        read_tools=["elasticsearch_logs", "prometheus_query", "zabbix_read", "knowledge_search"],
        default_handoffs=["application", "kubernetes", "database", "dependency", "infrastructure"],
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
        change_context = dict(input_data.context or {})
        if input_data.time_range and "time_range" not in change_context:
            change_context["time_range"] = input_data.time_range
        change_analysis = build_change_correlation_analysis(
            deterministic_evidence,
            service_name=input_data.service_name,
            context=change_context,
        )
        evidence_ids = self.evidence_ids(input_data)
        auxiliary_full = self.auxiliary_context(input_data)
        auxiliary = self._bounded_prompt_value(auxiliary_full)
        peer_full = self._peer_context(input_data)
        peer_context = self._bounded_prompt_value(peer_full)
        missing = self.missing_evidence_for(input_data, self.spec.required_evidence_types)

        prompt = f"""You are the change specialist and a senior Change Intelligence / Regression Correlation Investigator in a production AIOps platform.
LIVE EVIDENCE is authoritative. RAG/Memory and PEER OPERATIONAL CONTEXT are auxiliary only. Never inherit peer confidence or treat historical similarity as proof.
CHANGE_CORRELATION is deterministic pre-LLM analysis. A deployment merely preceding an incident is never sufficient for causality. Re-check candidate changes against measured before/after deltas, affected-scope overlap, reproducibility, canary/stable comparisons, alternative explanations and conflicting evidence.
The deterministic score includes: temporal proximity, post-change metric/log delta, affected-scope overlap, reproducibility/instance comparison, baseline/canary comparison, alternative explanations and conflicting evidence. Do not upgrade a weak score because the change looks plausible.
If only the newly changed/canary subset regresses while stable replicas remain healthy, that is stronger causal evidence. If new and stable versions fail together, investigate shared dependency/infrastructure/database/network causes instead of blaming the release.
Rollback may appear only as a rollback candidate supported by explicit evidence. Never execute rollback, deployment, scaling, restart, configuration mutation or any other write action. immediate_checks must be read-only investigation steps.
Focus areas: {json.dumps(self.spec.focus)}
Return one JSON object with keys: severity, health_status, findings, affected_components,
probable_dependencies, blast_radius, hypotheses, missing_evidence, handoff_agents,
immediate_checks, escalation_target, risk_level, uncertainty_reason, confidence.
Each hypothesis: hypothesis, probability, evidence_ids, conflicting_evidence_ids,
falsification_checks, impacted_components, recommended_next_evidence.
Only cite LIVE EVIDENCE IDs. Do not call a change root cause solely because it happened before the incident.
Incident={input_data.incident_id}
Service={input_data.service_name}
Summary={input_data.evidence_summary}
CHANGE_CORRELATION={json.dumps(sanitize_prompt_value(change_analysis), default=str)}
DETERMINISTIC_ANALYSIS={json.dumps(sanitize_prompt_value(deterministic), default=str)}
LIVE_EVIDENCE={json.dumps(prompt_evidence, default=str)}
AUXILIARY_CONTEXT={json.dumps(auxiliary, default=str)}
PEER_OPERATIONAL_CONTEXT={json.dumps(peer_context, default=str)}"""

        structured_failed = False
        try:
            result = await self.generate_structured(prompt)
        except Exception as exc:
            structured_failed = True
            logger.error(f"change structured analysis failed: {exc}")
            candidate_ids = [
                str(row.get("change_id")) for row in change_analysis.get("candidate_changes", [])
                if isinstance(row, dict) and row.get("change_id")
            ]
            result = {
                "severity": "unknown",
                "health_status": "unknown",
                "findings": [f"change candidate {cid}" for cid in candidate_ids[:6]],
                "affected_components": [input_data.service_name] if input_data.service_name else [],
                "probable_dependencies": [],
                "blast_radius": "unknown",
                "hypotheses": [],
                "missing_evidence": ["successful structured change analysis"],
                "handoff_agents": list(self.spec.default_handoffs),
                "immediate_checks": ["Inspect before/after metrics and compare changed instances with stable controls"],
                "escalation_target": "change-operator",
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
        actions = self.normalize_list(result.get("immediate_checks"), settings.AGENT_MAX_RECOMMENDATIONS)
        coverage = self.evidence_coverage(len(evidence), all_missing)
        handoffs = self.normalize_list(result.get("handoff_agents"), 6)
        for alt in change_analysis.get("alternative_causes", []):
            cause = str(alt.get("cause", "")) if isinstance(alt, dict) else ""
            target = {
                "dependency_outage": "dependency",
                "infrastructure_fault": "infrastructure",
                "network_fault": "network",
                "storage_fault": "storage",
                "database_fault": "database",
            }.get(cause)
            if target and target not in handoffs and len(handoffs) < 6:
                handoffs.append(target)
        for hint in deterministic.get("suggested_handoffs", []):
            target = str(hint.get("agent", "")) if isinstance(hint, dict) else ""
            if target and target != self.name and target not in handoffs and len(handoffs) < 6:
                handoffs.append(target)
        if not handoffs:
            handoffs = list(self.spec.default_handoffs)

        return AgentOutput(
            agent_name=self.name,
            finding_type="change_analysis",
            statement=("Change evidence: " + ("; ".join(findings) if findings else "no causally supported change regression yet"))[:600],
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
            escalation_target=str(result.get("escalation_target") or "change-operator"),
            risk_level=str(result.get("risk_level", "low")).lower(),
            uncertainty_reason=str(result.get("uncertainty_reason") or ("missing_evidence" if all_missing else "")) or None,
            requires_human_review=self.human_review_required(confidence, all_missing),
            analysis_details={
                "focus": self.spec.focus,
                "change_analysis": change_analysis,
                "candidate_changes": change_analysis.get("candidate_changes", []),
                "change_correlation_score": change_analysis.get("change_correlation_score", 0.0),
                "before_after_deltas": change_analysis.get("before_after_deltas", []),
                "alternative_causes": change_analysis.get("alternative_causes", []),
                "rollback_candidate_evidence": change_analysis.get("rollback_candidate_evidence", []),
                "simultaneous_changes": change_analysis.get("simultaneous_changes", []),
                "next_best_evidence": change_analysis.get("next_best_evidence", []),
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
                "execution_boundary": "analysis_only_no_rollback_execution",
                "causal_policy": change_analysis.get("policy"),
            },
            model_metadata=self._last_model_metadata,
        )
