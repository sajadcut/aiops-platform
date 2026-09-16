from __future__ import annotations

import json
from typing import List, Optional

from agents.identity.engine import build_identity_reliability_analysis
from agents.identity.safety import identity_prompt_evidence, redact_identity_value
from agents.shared.base import AgentInput, AgentOutput, OperationalHypothesis
from agents.shared.domain_agent import DomainDiagnosticAgent, DomainSpec
from agents.shared.intelligence import build_deterministic_analysis
from domain.contracts.config import settings
from domain.contracts.logging import logger
from integrations.llm.base import LLMAdapter


class IdentityAgent(DomainDiagnosticAgent):
    spec = DomainSpec(
        name="identity",
        description="Deep Identity/IAM/OIDC Diagnostic Specialist with deterministic authentication-chain analysis",
        focus=[
            "Client -> DNS/TLS -> IdP/OIDC discovery -> token issuance -> JWKS/signature -> claims -> authorization/role mapping",
            "authentication failure rate versus authorization denial rate and 401/403 separation",
            "OIDC discovery reachability, issuer/audience mismatch and signature-algorithm mismatch",
            "JWKS reachability, missing/rotated signing key and incident-time rotation correlation",
            "token exp/nbf and clock-skew symptoms without exposing token material",
            "scope, role, group and RBAC mapping",
            "IdP latency/outage and callback/redirect symptoms when evidenced",
            "certificate expiry/renewal, trust-chain/CA, TLS handshake and DNS dependencies",
            "mandatory redaction of tokens, credentials, secrets, private keys and Authorization headers",
        ],
        required_evidence_types=["log"],
        read_tools=["elasticsearch_logs", "prometheus_query", "zabbix_read", "knowledge_search"],
        default_handoffs=["security", "application", "network", "dependency"],
    )

    def __init__(self, llm_adapter: Optional[LLMAdapter] = None):
        super().__init__(llm_adapter)

    async def analyze(self, input_data: AgentInput) -> AgentOutput:
        evidence = self.evidence_items(input_data)
        prompt_evidence = identity_prompt_evidence(evidence, settings.AGENT_MAX_EVIDENCE_ITEMS)
        deterministic = build_deterministic_analysis(
            self.name,
            evidence,
            required_types=self.spec.required_evidence_types,
            service_name=input_data.service_name,
        )
        identity_context = dict(input_data.context or {})
        if input_data.time_range and "time_range" not in identity_context:
            identity_context["time_range"] = input_data.time_range
        identity_analysis = build_identity_reliability_analysis(
            evidence,
            service_name=input_data.service_name,
            context=identity_context,
        )
        evidence_ids = self.evidence_ids(input_data)
        auxiliary_full = self.auxiliary_context(input_data)
        auxiliary = self._bounded_prompt_value(redact_identity_value(auxiliary_full))
        peer_full = self._peer_context(input_data)
        peer_context = self._bounded_prompt_value(redact_identity_value(peer_full))
        missing = self.missing_evidence_for(input_data, self.spec.required_evidence_types)

        safe_summary = redact_identity_value(input_data.evidence_summary)
        safe_identity_analysis = redact_identity_value(identity_analysis)
        safe_deterministic = redact_identity_value(deterministic)
        prompt = f"""You are the identity specialist and a senior Identity/IAM/OIDC Diagnostic Specialist in a production AIOps platform.
LIVE EVIDENCE is authoritative. RAG/Memory and PEER OPERATIONAL CONTEXT are auxiliary only. Never inherit peer confidence or causal claims; validate them against LIVE EVIDENCE IDs.
IDENTITY_ANALYSIS is deterministic pre-LLM analysis of the authentication chain: Client -> DNS/TLS -> IdP/OIDC discovery -> Token issuance -> JWKS/signature validation -> Claims -> Authorization/role mapping. Do not skip a stage merely because a later symptom is visible.
Treat 401 as authentication-path evidence and 403 as authorization-path evidence unless stronger explicit evidence says otherwise. Never collapse expired token, not-before/clock skew, invalid signature, missing signing key, JWKS outage, wrong audience, issuer mismatch, algorithm mismatch, insufficient role and TLS/certificate failure into one generic authentication error.
Critical credential rule: full tokens, JWTs, secrets, private keys, Authorization headers, cookies, client assertions, code verifiers and credentials must never appear in prompt output, audit-oriented analysis details or recommendations. Reason only from metadata such as exp/nbf, issuer, audience, alg, kid presence and validation result.
Use IDENTITY_ANALYSIS.jwks_signature_analysis.rotation_timeline to compare JWKS/key rotation with incident onset, but temporal proximity alone is not causal proof. Require missing-key/signature/key-resolution corroboration.
If cryptographic authentication is healthy but access is denied, investigate role/scope/group/RBAC mapping and use Security/Application peer context as auxiliary input; do not relabel that situation as an authentication failure.
A certificate warning is not enough to claim a TLS root cause unless expiry/trust-chain/handshake evidence supports it. DNS/IdP outages remain dependency hypotheses until localized with live evidence.
Focus areas: {json.dumps(self.spec.focus)}
Return one JSON object with keys: severity, health_status, findings, affected_components,
probable_dependencies, blast_radius, hypotheses, missing_evidence, handoff_agents,
immediate_checks, escalation_target, risk_level, uncertainty_reason, confidence.
Each hypothesis: hypothesis, probability, evidence_ids, conflicting_evidence_ids,
falsification_checks, impacted_components, recommended_next_evidence.
Only cite LIVE EVIDENCE IDs. immediate_checks are read-only. Never execute credential rotation, revocation, role changes or IdP configuration changes directly.
Incident={input_data.incident_id}
Service={input_data.service_name}
Summary={safe_summary}
IDENTITY_ANALYSIS={json.dumps(safe_identity_analysis, default=str)}
DETERMINISTIC_ANALYSIS={json.dumps(safe_deterministic, default=str)}
LIVE_EVIDENCE={json.dumps(prompt_evidence, default=str)}
AUXILIARY_CONTEXT={json.dumps(auxiliary, default=str)}
PEER_OPERATIONAL_CONTEXT={json.dumps(peer_context, default=str)}"""

        structured_failed = False
        try:
            result = await self.generate_structured(prompt)
        except Exception as exc:
            structured_failed = True
            logger.error(f"identity structured analysis failed: {exc}")
            result = {
                "severity": "unknown",
                "health_status": "unknown",
                "findings": [str(row.get("code")) for row in identity_analysis.get("cause_candidates", []) if isinstance(row, dict)][:8],
                "affected_components": [input_data.service_name] if input_data.service_name else [],
                "probable_dependencies": [],
                "blast_radius": "unknown",
                "hypotheses": [],
                "missing_evidence": ["successful structured identity analysis"],
                "handoff_agents": list(identity_analysis.get("handoff_candidates") or self.spec.default_handoffs),
                "immediate_checks": ["Inspect credential-safe authentication-chain metadata and the next highest-information evidence gap"],
                "escalation_target": "identity-operator",
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
                hypothesis=str(redact_identity_value(item["hypothesis"])),
                probability=self.safe_confidence(item.get("probability", 0), len(evidence), all_missing, len(conflicting)),
                evidence_ids=[str(x) for x in item.get("evidence_ids", []) if str(x) in evidence_ids],
                conflicting_evidence_ids=conflicting,
                falsification_checks=self.normalize_list(redact_identity_value(item.get("falsification_checks", [])), 5),
                impacted_components=self.normalize_list(redact_identity_value(item.get("impacted_components", [])), 6),
                recommended_next_evidence=self.normalize_list(redact_identity_value(item.get("recommended_next_evidence", [])), 6),
            ))

        confidence = self.safe_confidence(result.get("confidence"), len(evidence), all_missing, conflicts)
        findings = self.normalize_list(redact_identity_value(result.get("findings", [])), 10)
        actions = self.normalize_list(redact_identity_value(result.get("immediate_checks", [])), settings.AGENT_MAX_RECOMMENDATIONS)
        coverage = self.evidence_coverage(len(evidence), all_missing)
        handoffs = self.normalize_list(result.get("handoff_agents"), 6)
        for target in identity_analysis.get("handoff_candidates", []):
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
            finding_type="identity_analysis",
            statement=("Identity evidence: " + ("; ".join(findings) if findings else "no confirmed identity-local fault yet"))[:600],
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
            probable_dependencies=self.normalize_list(redact_identity_value(result.get("probable_dependencies", [])), 8),
            affected_components=self.normalize_list(redact_identity_value(result.get("affected_components", [])), 8),
            blast_radius=str(redact_identity_value(result.get("blast_radius", "unknown"))),
            escalation_target=str(result.get("escalation_target") or "identity-operator"),
            risk_level=str(result.get("risk_level", "low")).lower(),
            uncertainty_reason=str(redact_identity_value(result.get("uncertainty_reason") or ("missing_evidence" if all_missing else ""))) or None,
            requires_human_review=self.human_review_required(confidence, all_missing),
            analysis_details={
                "focus": self.spec.focus,
                "identity_analysis": identity_analysis,
                "authentication_chain": identity_analysis.get("authentication_chain", []),
                "rates": identity_analysis.get("rates", {}),
                "oidc_analysis": identity_analysis.get("oidc_analysis", {}),
                "jwks_signature_analysis": identity_analysis.get("jwks_signature_analysis", {}),
                "token_claim_analysis": identity_analysis.get("token_claim_analysis", {}),
                "tls_dns_analysis": identity_analysis.get("tls_dns_analysis", {}),
                "cause_candidates": identity_analysis.get("cause_candidates", []),
                "causal_attribution": identity_analysis.get("causal_attribution"),
                "next_best_evidence": identity_analysis.get("next_best_evidence", []),
                "deterministic_analysis": redact_identity_value(deterministic),
                "evidence_gap_matrix": redact_identity_value(deterministic.get("evidence_gap_matrix", {})),
                "knowledge_context_count": len(auxiliary_full["knowledge_rag"]),
                "memory_context_count": len(auxiliary_full["operational_memory"]),
                "peer_finding_count": len(peer_full["findings"]),
                "peer_disagreement": bool(peer_full["coordination"].get("disagreement")),
                "conflicting_evidence_count": conflicts,
                "prompt_evidence_count": len(prompt_evidence),
                "structured_analysis_failed": structured_failed,
                "credential_redaction": "mandatory",
                "execution_boundary": "analysis_only",
            },
            model_metadata=self._last_model_metadata,
        )
