import json
from typing import List, Optional

from agents.shared.base import AgentInput, AgentOutput, BaseAgent, OperationalHypothesis, RecommendedAction
from domain.contracts.config import settings
from domain.contracts.logging import logger
from integrations.llm.base import LLMAdapter


class SecurityAgent(BaseAgent):
    def __init__(self, llm_adapter: Optional[LLMAdapter] = None):
        super().__init__(llm_adapter)

    @property
    def name(self) -> str:
        return "security"

    @property
    def description(self) -> str:
        return "SOC analysis: authentication, authorization, suspicious activity, exposure and security policy"

    @property
    def allowed_tools(self) -> List[str]:
        return ["elasticsearch_logs", "zabbix_read", "knowledge_search"]

    async def analyze(self, input_data: AgentInput) -> AgentOutput:
        logger.info(f"SecurityAgent analyzing: {input_data.incident_id}")
        evidence = self.evidence_items(input_data)
        evidence_ids = self.evidence_ids(input_data)
        auxiliary = self.auxiliary_context(input_data)
        logs = [item for item in evidence if str(item.get("type", "")).lower() == "log"]
        alerts = [item for item in evidence if str(item.get("type", "")).lower() in {"alert", "event"}]
        missing = self.missing_evidence_for(input_data, ["log"])
        prompt = f"""You are a senior SOC analyst. LIVE EVIDENCE is authoritative. RAG/Memory are auxiliary only. Never assert compromise, exfiltration, brute force, credential theft, lateral movement or policy violation without direct live evidence. Distinguish observations from hypotheses.
Return JSON keys: severity, health_status, findings, authentication_signals, authorization_signals, suspicious_signals, exposure_signals, policy_signals, probable_dependencies, affected_components, blast_radius, hypotheses, missing_evidence, handoff_agents, immediate_checks, containment_recommendations, escalation_target, risk_level, uncertainty_reason, confidence.
Hypotheses entries: hypothesis, probability, evidence_ids, conflicting_evidence_ids, falsification_checks, impacted_components, recommended_next_evidence. Only live evidence IDs may be cited. immediate_checks are read-only. containment_recommendations are write recommendations and MUST remain approval-gated.
Incident={input_data.incident_id}\nService={input_data.service_name}\nSummary={input_data.evidence_summary}\nLIVE_EVIDENCE={json.dumps(evidence, default=str)}\nAUXILIARY_CONTEXT={json.dumps(auxiliary, default=str)}\nContextSummary={json.dumps(input_data.context.get('summary', {}), default=str)}"""
        try:
            result = await self.generate_structured(prompt)
        except Exception as exc:
            logger.error(f"SecurityAgent analysis failed: {exc}")
            result = {"severity":"unknown","health_status":"unknown","findings":[],"suspicious_signals":[],"affected_components":[],"blast_radius":"unknown","hypotheses":[],"handoff_agents":["identity"],"immediate_checks":["Collect authentication and authorization logs"],"containment_recommendations":[],"uncertainty_reason":"structured_analysis_failed","confidence":0.0}
            missing = sorted(set(missing + ["successful structured security analysis"]))

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
        immediate = self.normalize_list(result.get("immediate_checks"), settings.AGENT_MAX_RECOMMENDATIONS)
        containment = self.normalize_list(result.get("containment_recommendations"), settings.AGENT_MAX_RECOMMENDATIONS)
        severity = str(result.get("severity", "unknown")).lower()
        severe = severity in {"critical", "high"}
        recommended_actions = self.analysis_only_actions(immediate)
        recommended_actions.extend([
            RecommendedAction(action=action, purpose="containment", risk_level="high" if severe else "medium", requires_approval=True, read_only=False)
            for action in containment
        ])
        suspicious = self.normalize_list(result.get("suspicious_signals"), 6)
        findings = self.normalize_list(result.get("findings"), 10) or suspicious
        statement = "Security evidence indicates " + ("; ".join(findings) if findings else "no confirmed malicious pattern yet")
        return AgentOutput(
            agent_name=self.name,
            finding_type=f"security_{severity}",
            statement=statement[:600],
            severity=severity,
            health_status=str(result.get("health_status", "unknown")).lower(),
            confidence=confidence,
            evidence_ids=evidence_ids,
            evidence_count=len(evidence),
            evidence_coverage=self.evidence_coverage(len(evidence), all_missing),
            findings=findings,
            recommendations=immediate + containment,
            recommended_actions=recommended_actions,
            hypotheses=hypotheses,
            missing_evidence=all_missing,
            handoff_agents=self.normalize_list(result.get("handoff_agents"), 6),
            probable_dependencies=self.normalize_list(result.get("probable_dependencies"), 8),
            affected_components=self.normalize_list(result.get("affected_components"), 8),
            blast_radius=str(result.get("blast_radius", "unknown")),
            escalation_target=str(result.get("escalation_target") or "soc"),
            risk_level=str(result.get("risk_level", "high" if severe else "medium")).lower(),
            uncertainty_reason=str(result.get("uncertainty_reason") or ("missing_evidence" if all_missing else "")) or None,
            requires_approval=bool(containment),
            requires_human_review=self.human_review_required(confidence, all_missing, severe=severe),
            analysis_details={
                "authentication_signals": result.get("authentication_signals", []),
                "authorization_signals": result.get("authorization_signals", []),
                "suspicious_signals": suspicious,
                "exposure_signals": result.get("exposure_signals", []),
                "policy_signals": result.get("policy_signals", []),
                "log_evidence_count": len(logs),
                "alert_evidence_count": len(alerts),
                "knowledge_context_count": len(auxiliary["knowledge_rag"]),
                "memory_context_count": len(auxiliary["operational_memory"]),
                "conflicting_evidence_count": conflict_count,
            },
            model_metadata=self._last_model_metadata,
        )
