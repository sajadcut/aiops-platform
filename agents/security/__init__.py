import json
from typing import Any, Dict, List, Mapping, Optional

from agents.security.engine import build_security_analysis
from agents.security.safety import redact_security_value, security_prompt_evidence
from agents.shared.base import AgentInput, AgentOutput, BaseAgent, OperationalHypothesis, RecommendedAction
from agents.shared.intelligence import build_deterministic_analysis
from domain.contracts.config import settings
from domain.contracts.logging import logger
from integrations.llm.base import LLMAdapter


_PROHIBITED_UNCONFIRMED_CLAIMS = (
    "confirmed compromise", "compromise confirmed", "confirmed breach", "breach confirmed",
    "confirmed credential theft", "confirmed exfiltration",
)


def _guard_security_claim(value: Any, classification: str) -> str:
    text = str(value or "").strip()
    if classification == "confirmed_compromise":
        return text
    if any(token in text.lower() for token in _PROHIBITED_UNCONFIRMED_CLAIMS):
        return "Compromise was proposed as a hypothesis but is not confirmed by current live evidence"
    return text


def _as_list(value: Any) -> List[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, tuple):
        return list(value)
    return [value]


def _rich_hypothesis(item: Mapping[str, Any], live_ids: set[str], confidence_cap: float) -> Dict[str, Any]:
    supporting = [str(x) for x in _as_list(item.get("evidence_ids") or item.get("supporting_evidence_ids")) if str(x) in live_ids]
    conflicting = [str(x) for x in _as_list(item.get("conflicting_evidence_ids")) if str(x) in live_ids]
    try:
        confidence = max(0.0, min(float(item.get("confidence", item.get("probability", 0.0))), confidence_cap))
    except (TypeError, ValueError):
        confidence = 0.0
    return {
        "hypothesis": str(item.get("hypothesis") or "")[:420],
        "supporting_evidence_ids": supporting[:20],
        "conflicting_evidence_ids": conflicting[:20],
        "alternative_benign_explanations": [str(x)[:320] for x in _as_list(item.get("alternative_benign_explanations") or item.get("alternative_benign_explanation"))[:4] if x],
        "required_verification": [str(x)[:320] for x in _as_list(item.get("required_verification") or item.get("verification") or item.get("falsification_checks"))[:6] if x],
        "affected_identities": [str(x)[:180] for x in _as_list(item.get("affected_identities"))[:20] if x],
        "affected_assets": [str(x)[:180] for x in _as_list(item.get("affected_assets") or item.get("impacted_components"))[:20] if x],
        "confidence": confidence,
    }


class SecurityAgent(BaseAgent):
    def __init__(self, llm_adapter: Optional[LLMAdapter] = None):
        super().__init__(llm_adapter)

    @property
    def name(self) -> str:
        return "security"

    @property
    def description(self) -> str:
        return "Evidence-driven security incident analysis with conservative compromise classification and approval-gated containment"

    @property
    def allowed_tools(self) -> List[str]:
        return ["elasticsearch_logs", "zabbix_read", "knowledge_search"]

    async def analyze(self, input_data: AgentInput) -> AgentOutput:
        logger.info(f"SecurityAgent analyzing: {input_data.incident_id}")
        evidence = self.evidence_items(input_data)
        evidence_ids = self.evidence_ids(input_data)
        live_ids = set(evidence_ids)
        auxiliary = self.auxiliary_context(input_data)
        prompt_evidence = security_prompt_evidence(evidence, settings.AGENT_MAX_EVIDENCE_ITEMS)
        deterministic = build_deterministic_analysis("security", evidence, ["log"], input_data.service_name)
        security_analysis = build_security_analysis(evidence, service_name=input_data.service_name, context=input_data.context)
        classification = dict(security_analysis.get("classification") or {})
        security_state = str(classification.get("level") or "insufficient_evidence")
        confidence_cap = float(classification.get("confidence_cap") or 0.35)
        missing = self.missing_evidence_for(input_data, ["log"])

        prompt = f"""You are a senior evidence-driven SOC incident analyst. LIVE EVIDENCE is authoritative. RAG/Memory and peer-agent output are auxiliary only. Never assert compromise, exfiltration, brute force, credential theft, lateral movement or malicious intent without direct live evidence.
SECURITY_ANALYSIS is deterministic and owns the maximum conclusion class. Allowed hierarchy: insufficient_evidence -> observed_suspicious_event -> policy_violation -> probable_attack -> confirmed_compromise. Never upgrade beyond SECURITY_ANALYSIS.classification.level. A single alert never establishes confirmed compromise.
Investigate auth/authz trends, process trees and unexpected binaries when telemetry exists, privilege escalation, anomalous user/service-account behavior, unusual source/destination/outbound/listeners, container/runtime events, policy violations, repeated denies, secret/token USAGE METADATA only, file/path access only when evidenced, runtime chronology, and identity+network+application correlation.
Actively test benign explanations: expired tokens, RBAC/config drift, approved automation/deployments, scanners and duplicate/noisy logs. MITRE-style stages remain hypotheses unless SECURITY_ANALYSIS says evidence is sufficient. Never reveal credential values.
Return JSON keys: severity, health_status, findings, authentication_signals, authorization_signals, suspicious_signals, exposure_signals, policy_signals, probable_dependencies, affected_components, hypotheses, missing_evidence, handoff_agents, immediate_checks, containment_recommendations, escalation_target, risk_level, uncertainty_reason, confidence.
Each hypothesis must include hypothesis, probability, evidence_ids, conflicting_evidence_ids, falsification_checks, recommended_next_evidence, alternative_benign_explanations, required_verification, affected_identities, affected_assets. Only live evidence IDs may be cited. immediate_checks are read-only. revoke/block/isolate/rotate actions are recommendations and require approval.
Incident={input_data.incident_id}\nService={input_data.service_name}\nSummary={input_data.evidence_summary}\nDETERMINISTIC_ANALYSIS={json.dumps(redact_security_value(deterministic), default=str)}\nSECURITY_ANALYSIS={json.dumps(redact_security_value(security_analysis), default=str)}\nLIVE_EVIDENCE={json.dumps(prompt_evidence, default=str)}\nAUXILIARY_CONTEXT={json.dumps(redact_security_value(auxiliary), default=str)}\nContextSummary={json.dumps(redact_security_value(input_data.context.get('summary', {})), default=str)}"""
        try:
            result = await self.generate_structured(prompt)
        except Exception as exc:
            logger.error(f"SecurityAgent analysis failed: {exc}")
            result = {
                "severity": "unknown", "health_status": "unknown", "findings": [], "suspicious_signals": [],
                "affected_components": [], "hypotheses": [], "handoff_agents": ["identity"],
                "immediate_checks": ["Collect authentication and authorization logs"], "containment_recommendations": [],
                "uncertainty_reason": "structured_analysis_failed", "confidence": 0.0,
            }
            missing = sorted(set(missing + ["successful structured security analysis"]))

        engine_missing: List[str] = []
        if security_state in {"insufficient_evidence", "observed_suspicious_event", "policy_violation"}:
            engine_missing = [
                str(row.get("evidence")) for row in security_analysis.get("next_best_evidence", [])[:3]
                if isinstance(row, Mapping) and row.get("evidence")
            ]
        all_missing = sorted(set(missing + engine_missing + self.normalize_list(result.get("missing_evidence"), 8)))

        rich_hypotheses: List[Dict[str, Any]] = []
        hypotheses: List[OperationalHypothesis] = []
        conflict_count = 0
        source_hypotheses = [row for row in result.get("hypotheses", []) if isinstance(row, Mapping) and row.get("hypothesis")]
        if not source_hypotheses:
            source_hypotheses = [row for row in security_analysis.get("security_hypotheses", []) if isinstance(row, Mapping)]
        for item in source_hypotheses[: settings.AGENT_MAX_HYPOTHESES]:
            rich = _rich_hypothesis(item, live_ids, confidence_cap)
            rich["hypothesis"] = _guard_security_claim(rich["hypothesis"], security_state)
            rich_hypotheses.append(rich)
            conflict_count += len(rich["conflicting_evidence_ids"])
            hypotheses.append(OperationalHypothesis(
                hypothesis=rich["hypothesis"],
                probability=self.safe_confidence(rich["confidence"], len(evidence), all_missing, len(rich["conflicting_evidence_ids"])),
                evidence_ids=rich["supporting_evidence_ids"],
                conflicting_evidence_ids=rich["conflicting_evidence_ids"],
                falsification_checks=rich["required_verification"][:5],
                impacted_components=list(dict.fromkeys(rich["affected_assets"] + rich["affected_identities"]))[:8],
                recommended_next_evidence=self.normalize_list(item.get("recommended_next_evidence"), 6) or engine_missing[:6],
            ))

        model_confidence = self.safe_confidence(result.get("confidence"), len(evidence), all_missing, conflict_count)
        confidence = min(model_confidence, confidence_cap)
        severity = str(result.get("severity", "unknown")).lower()
        severe = severity in {"critical", "high"}
        immediate = self.normalize_list(result.get("immediate_checks"), settings.AGENT_MAX_RECOMMENDATIONS)
        containment = self.normalize_list(result.get("containment_recommendations"), settings.AGENT_MAX_RECOMMENDATIONS)
        actions = self.analysis_only_actions(immediate)
        actions.extend([
            RecommendedAction(action=value, purpose="containment", risk_level="high" if severe else "medium", requires_approval=True, read_only=False)
            for value in containment
        ])

        suspicious = [_guard_security_claim(value, security_state) for value in self.normalize_list(result.get("suspicious_signals"), 8)]
        model_findings = [_guard_security_claim(value, security_state) for value in self.normalize_list(result.get("findings"), 10)]
        observed_codes = [
            str(row.get("code")) for row in security_analysis.get("security_events", [])[:10]
            if isinstance(row, Mapping) and row.get("code")
        ]
        findings = model_findings or suspicious or observed_codes

        handoffs = self.normalize_list(result.get("handoff_agents"), 6)
        for target in security_analysis.get("handoff_candidates", []):
            target = str(target)
            if target and target != self.name and target not in handoffs and len(handoffs) < 6:
                handoffs.append(target)
        for hint in deterministic.get("suggested_handoffs", []):
            target = str(hint.get("agent", "")) if isinstance(hint, dict) else ""
            if target and target != self.name and target not in handoffs and len(handoffs) < 6:
                handoffs.append(target)

        blast = security_analysis.get("blast_radius") if isinstance(security_analysis.get("blast_radius"), Mapping) else {}
        statement = f"Security classification={security_state}: " + (
            "; ".join(findings) if findings else str(classification.get("reason") or "no confirmed malicious pattern")
        )
        logs = [item for item in evidence if str(item.get("type", "")).lower() == "log"]
        alerts = [item for item in evidence if str(item.get("type", "")).lower() in {"alert", "event"}]
        return AgentOutput(
            agent_name=self.name,
            finding_type=f"security_{security_state}",
            statement=statement[:600],
            severity=severity,
            health_status=str(result.get("health_status", "unknown")).lower(),
            confidence=confidence,
            evidence_ids=evidence_ids,
            evidence_count=len(evidence),
            evidence_coverage=self.evidence_coverage(len(evidence), all_missing),
            findings=findings,
            recommendations=immediate + containment,
            recommended_actions=actions,
            hypotheses=hypotheses,
            missing_evidence=all_missing,
            handoff_agents=handoffs,
            probable_dependencies=self.normalize_list(result.get("probable_dependencies"), 8),
            affected_components=self.normalize_list(result.get("affected_components"), 8),
            blast_radius=str(blast.get("scope") or result.get("blast_radius") or "unknown"),
            escalation_target=str(result.get("escalation_target") or "soc"),
            risk_level=str(result.get("risk_level", "high" if severe else "medium")).lower(),
            uncertainty_reason=str(result.get("uncertainty_reason") or ("missing_evidence" if all_missing else "")) or None,
            requires_approval=bool(containment),
            requires_human_review=self.human_review_required(confidence, all_missing, severe=severe),
            analysis_details={
                "security_classification": security_state,
                "classification_reason": classification.get("reason"),
                "classification_confidence_cap": confidence_cap,
                "authentication_signals": result.get("authentication_signals", []),
                "authorization_signals": result.get("authorization_signals", []),
                "suspicious_signals": suspicious,
                "exposure_signals": result.get("exposure_signals", []),
                "policy_signals": result.get("policy_signals", []),
                "security_events": security_analysis.get("security_events", []),
                "authentication_failure_trend": security_analysis.get("authentication_failure_trend", {}),
                "authorization_denial_trend": security_analysis.get("authorization_denial_trend", {}),
                "runtime_timeline": security_analysis.get("runtime_timeline", []),
                "network_analysis": security_analysis.get("network_analysis", {}),
                "mitre_style_mapping": security_analysis.get("mitre_style_mapping", {}),
                "false_positive_analysis": security_analysis.get("false_positive_analysis", []),
                "security_hypotheses": rich_hypotheses,
                "blast_radius_scope": blast,
                "peer_security_context": security_analysis.get("peer_security_context", {}),
                "next_best_evidence": security_analysis.get("next_best_evidence", []),
                "security_evidence_level": deterministic.get("security_evidence_level"),
                "deterministic_analysis": deterministic,
                "security_analysis": security_analysis,
                "log_evidence_count": len(logs),
                "alert_evidence_count": len(alerts),
                "knowledge_context_count": len(auxiliary["knowledge_rag"]),
                "memory_context_count": len(auxiliary["operational_memory"]),
                "conflicting_evidence_count": conflict_count,
                "containment_policy": "recommendation_only; revoke/block/isolate require approval",
                "execution_boundary": "analysis_only",
            },
            model_metadata=self._last_model_metadata,
        )
