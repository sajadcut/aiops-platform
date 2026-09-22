from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional

from domain.contracts.config import settings
from .contracts import EMBEDDING_DOCUMENT_VERSION, MEMORY_SCHEMA_VERSION


class OperationalMemoryBuilder:
    """Build a bounded, sanitized, evidence-linked historical incident episode.

    The builder is deterministic. Historical Memory remains auxiliary context and
    never becomes current Evidence or execution authority.
    """

    SCHEMA_VERSION = MEMORY_SCHEMA_VERSION
    EMBEDDING_DOCUMENT_VERSION = EMBEDDING_DOCUMENT_VERSION
    ROOT_CAUSE_STATUSES = {"confirmed", "probable", "possible", "unconfirmed", "unknown"}
    CRITICAL_CONDITIONS = {"service_active", "port_listening", "tcp_reachable", "config_valid"}
    EXPECTED_RECOVERY_OVERHEAD = {"cpu_usage", "memory_usage"}
    SECRET_KEYS = {
        "password", "passwd", "pwd", "secret", "token", "api_key", "apikey",
        "authorization", "cookie", "private_key", "client_secret", "access_token",
        "refresh_token", "id_token",
    }
    SECRET_PATTERNS = (
        re.compile(r"(?i)\\b(authorization)\\s*:\\s*(bearer|basic)\\s+\\S+"),
        re.compile(r"(?i)\\b(api[_-]?key|password|passwd|secret|token)\\s*[:=]\\s*[^\\s,;]+"),
    )

    @classmethod
    def build(cls, state: Dict[str, Any]) -> Dict[str, Any]:
        context = dict(state.get("context") or {})
        incident = dict(context.get("incident") or {})
        trigger_signal = dict(context.get("trigger_signal") or {})
        execution_request = dict(state.get("execution_request") or {})
        execution_result = dict(state.get("execution_result") or {})
        verification_result = dict(state.get("verification_result") or {})
        approval = dict(state.get("approval") or {})
        asset = dict(
            context.get("asset_context")
            or (context.get("live_evidence") or {}).get("asset_context")
            or {}
        )

        service = str(
            state.get("service_name")
            or context.get("service")
            or incident.get("service")
            or "unknown"
        )
        pattern = str(
            state.get("evidence_summary")
            or incident.get("summary")
            or trigger_signal.get("summary")
            or f"{service} operational incident"
        ).strip()

        before_state = cls._numeric_map(verification_result.get("before_state"))
        after_state = cls._numeric_map(verification_result.get("after_state"))
        normalized_symptoms = cls._normalized_symptoms(before_state, pattern)
        incident_pattern = {
            "summary": cls._sanitize_string(pattern),
            "service": service,
            "before_state": before_state,
            "observed_faults": normalized_symptoms,
        }

        evidence = cls._evidence_items(state)
        evidence_refs = cls._evidence_refs(state, evidence, verification_result)
        evidence_sources = sorted({str(item.get("source") or "unknown") for item in evidence})
        evidence_types = sorted({str(item.get("type") or "unknown") for item in evidence})
        evidence_times = [
            str(item.get("timestamp") or item.get("observed_at") or "")
            for item in evidence
            if item.get("timestamp") or item.get("observed_at")
        ]
        evidence_provenance = {
            "evidence_refs": evidence_refs,
            "evidence_sources": evidence_sources,
            "evidence_types": evidence_types,
            "evidence_count": len(evidence),
            "evidence_time_window": {
                "first": min(evidence_times) if evidence_times else None,
                "last": max(evidence_times) if evidence_times else None,
            },
        }

        findings = [item for item in state.get("findings", []) if isinstance(item, dict)]
        coordination = dict(state.get("coordination") or {})
        triage = dict(state.get("triage_result") or {})
        investigation = {
            "investigation_summary": cls._investigation_summary(
                triage=triage,
                coordination=coordination,
                findings=findings,
            ),
            "triage": cls._sanitize_value(triage),
            "rca_synthesis": cls._sanitize_string(str(state.get("final_plan") or "")),
            "specialist_findings": cls._specialist_findings(findings),
            "investigated_hypotheses": cls._hypotheses(findings),
            "rejected_hypotheses": cls._sanitize_value(coordination.get("rejected_hypotheses") or []),
            "missing_evidence": cls._dedupe_strings(
                list(coordination.get("missing_evidence") or [])
                + [
                    gap
                    for finding in findings
                    for gap in (finding.get("missing_evidence") or [])
                ]
            ),
            "contradictions": cls._sanitize_value(coordination.get("contradictions") or []),
            "evidence_requests": cls._evidence_requests(findings),
            "contributing_factors": cls._contributing_factors(findings),
            "specialist_agents_used": sorted({
                str(item.get("agent_name") or item.get("agent") or "")
                for item in findings
                if item.get("agent_name") or item.get("agent")
            }),
            "evidence_rounds": int(state.get("evidence_rounds") or 0),
        }

        root_cause, root_cause_status, root_cause_confidence = cls._root_cause(findings, state)
        actual_remediation = cls._actual_remediation(
            execution_request=execution_request,
            execution_result=execution_result,
            approval=approval,
            service=service,
        )
        verification = cls._verification(verification_result)
        outcome_class = cls._outcome_class(execution_result, verification_result, state)
        verification_status = str(verification.get("status") or "").lower()
        if verification_status == "inconclusive" and outcome_class in {"failed_recovery", "execution_blocked"}:
            verification_status = "failed"
            verification["status"] = "failed"

        outcome = str(
            verification_result.get("message")
            or execution_result.get("reason")
            or execution_result.get("error")
            or outcome_class
        )
        trigger = {
            "source": trigger_signal.get("source") or incident.get("source"),
            "signal_type": trigger_signal.get("signal_type") or incident.get("signal_type"),
            "trigger_summary": cls._sanitize_string(
                str(trigger_signal.get("summary") or incident.get("summary") or pattern)
            ),
            "severity": trigger_signal.get("severity") or incident.get("severity"),
            "trigger_timestamp": trigger_signal.get("timestamp") or incident.get("started_at"),
        }
        trigger["trigger_signature"] = cls._signature(trigger)

        scope = {
            "asset_type": asset.get("asset_type"),
            "asset_id": asset.get("asset_id") or asset.get("id"),
            "hostname": asset.get("hostname") or asset.get("host"),
            "fqdn": asset.get("fqdn"),
            "platform": asset.get("platform"),
            "namespace": asset.get("namespace"),
            "service_version": asset.get("service_version") or context.get("service_version"),
            "configuration_fingerprint": (
                asset.get("configuration_fingerprint")
                or context.get("configuration_fingerprint")
            ),
        }

        reusable_lesson = cls._reusable_lesson(
            service=service,
            root_cause_status=root_cause_status,
            actual_remediation=actual_remediation,
            verification=verification,
            outcome_class=outcome_class,
        )
        episode: Dict[str, Any] = {
            "memory_schema_version": cls.SCHEMA_VERSION,
            "incident_id": state.get("incident_id"),
            "environment": settings.APP_ENV,
            "service_scope": service,
            **scope,
            "trigger": cls._sanitize_value(trigger),
            "incident_pattern": cls._sanitize_value(incident_pattern),
            "normalized_symptoms": cls._sanitize_value(normalized_symptoms),
            "symptom_signature": cls._signature(normalized_symptoms),
            "investigation": cls._sanitize_value(investigation),
            "evidence_provenance": cls._sanitize_value(evidence_provenance),
            "root_cause": cls._sanitize_string(root_cause),
            "root_cause_status": root_cause_status,
            "root_cause_confidence": root_cause_confidence,
            "causal_factors": cls._sanitize_value(cls._causal_factors(findings)),
            "contributing_factors": cls._sanitize_value(investigation["contributing_factors"]),
            "actual_remediation": cls._sanitize_value(actual_remediation),
            "verification": cls._sanitize_value(verification),
            "verification_result": verification_status or "inconclusive",
            "outcome": cls._sanitize_string(outcome),
            "memory_outcome_class": outcome_class,
            "reusable_lesson": cls._sanitize_string(reusable_lesson),
            "lifecycle_status": "active",
            "valid_from": datetime.now(timezone.utc),
            # Backward-compatible projection.
            "pattern": cls._sanitize_string(pattern),
            "symptoms": cls._sanitize_value({
                "normalized": normalized_symptoms,
                "findings": findings,
                "evidence_refs": evidence_refs,
            }),
            "action": cls._sanitize_string(
                str(actual_remediation.get("action") or state.get("final_plan") or "")
            ),
        }
        embedding_document = cls.build_embedding_document(episode)
        episode["embedding_document"] = embedding_document
        episode["embedding_document_version"] = cls.EMBEDDING_DOCUMENT_VERSION
        episode["embedding_text_hash"] = hashlib.sha256(
            embedding_document.encode("utf-8")
        ).hexdigest()
        episode["search_document"] = cls._search_document(episode)
        episode["episode_fingerprint"] = cls._episode_fingerprint(episode)
        return episode

    @classmethod
    def build_embedding_document(cls, episode: Dict[str, Any]) -> str:
        remediation = episode.get("actual_remediation") or {}
        verification = episode.get("verification") or {}
        sections = [
            ("Service", episode.get("service_scope")),
            ("Environment", episode.get("environment")),
            ("Incident Pattern", episode.get("incident_pattern")),
            ("Observed Symptoms", episode.get("normalized_symptoms")),
            ("Investigation", {
                "summary": (episode.get("investigation") or {}).get("investigation_summary"),
                "triage": (episode.get("investigation") or {}).get("triage"),
                "rca_synthesis": (episode.get("investigation") or {}).get("rca_synthesis"),
                "hypotheses": (episode.get("investigation") or {}).get("investigated_hypotheses"),
                "missing_evidence": (episode.get("investigation") or {}).get("missing_evidence"),
                "contradictions": (episode.get("investigation") or {}).get("contradictions"),
            }),
            ("Historical Root Cause", {
                "status": episode.get("root_cause_status"),
                "summary": episode.get("root_cause"),
            }),
            ("Contributing Factors", episode.get("contributing_factors")),
            ("Actual Remediation", {
                "tool": remediation.get("tool_name"),
                "action": remediation.get("action"),
                "target": remediation.get("target"),
                "service": remediation.get("service"),
                "runbook_id": remediation.get("runbook_id"),
                "runbook_version": remediation.get("runbook_version"),
                "execution_success": remediation.get("execution_success"),
            }),
            ("Verification", {
                "status": verification.get("status"),
                "recovered_signals": verification.get("recovered_signals"),
                "remaining_symptoms": verification.get("remaining_symptoms"),
                "expected_side_effects": verification.get("expected_side_effects"),
                "unexpected_regressions": verification.get("unexpected_regressions"),
            }),
            ("Outcome", episode.get("memory_outcome_class")),
            ("Reusable Lesson", episode.get("reusable_lesson")),
        ]
        text_value = "\n\n".join(
            f"[{name}]\n{cls._stable_text(value)}"
            for name, value in sections
            if value not in (None, "", [], {})
        )
        return text_value[: int(getattr(settings, "MEMORY_MAX_EMBEDDING_TEXT_CHARS", 12000))]

    @classmethod
    def _root_cause(
        cls, findings: List[Dict[str, Any]], state: Dict[str, Any]
    ) -> tuple[str, str, float]:
        explicit: List[tuple[float, str, str]] = []
        evidence_linked: List[tuple[float, str]] = []
        for finding in findings:
            evidence_ids = [str(x) for x in finding.get("evidence_ids", []) if x]
            confidence = float(finding.get("confidence") or 0.0)
            statement = str(
                finding.get("statement") or finding.get("summary") or ""
            ).strip()
            details = finding.get("analysis_details") or {}
            status = str(
                finding.get("root_cause_status")
                or (details.get("root_cause_status") if isinstance(details, dict) else "")
                or ""
            ).strip().lower()
            if status in cls.ROOT_CAUSE_STATUSES and evidence_ids and statement:
                explicit.append((confidence, status, statement))
            if evidence_ids and statement:
                evidence_linked.append((confidence, statement))

        if explicit:
            confidence, status, statement = max(explicit, key=lambda item: item[0])
            return statement, status, round(confidence, 4)

        triage = dict(state.get("triage_result") or {})
        candidate = str(
            triage.get("likely_cause")
            or triage.get("summary")
            or max(evidence_linked, default=(0.0, ""))[1]
            or "Historical root cause was not conclusively established."
        ).strip()
        confidence = float(triage.get("confidence") or state.get("confidence") or 0.0)
        if not candidate:
            return "Historical root cause is unknown.", "unknown", 0.0
        # Successful recovery never upgrades historical cause confidence.
        return candidate, "unconfirmed", round(confidence, 4)

    @staticmethod
    def _numeric_map(value: Any) -> Dict[str, float]:
        result: Dict[str, float] = {}
        if not isinstance(value, dict):
            return result
        for key, raw in value.items():
            try:
                result[str(key)] = float(raw)
            except (TypeError, ValueError):
                continue
        return result

    @classmethod
    def _normalized_symptoms(cls, before: Dict[str, float], pattern: str) -> List[str]:
        symptoms: List[str] = []
        for key in sorted(cls.CRITICAL_CONDITIONS):
            if key in before and before[key] < 1.0:
                symptoms.append(f"{key}=false")
        if not symptoms and pattern:
            symptoms.append(cls._sanitize_string(pattern)[:500])
        return symptoms

    @classmethod
    def _verification(cls, result: Dict[str, Any]) -> Dict[str, Any]:
        before = cls._numeric_map(result.get("before_state"))
        after = cls._numeric_map(result.get("after_state"))
        directions = (
            {str(k): str(v) for k, v in result.get("metric_directions", {}).items()}
            if isinstance(result.get("metric_directions"), dict)
            else {}
        )
        recovered: List[str] = []
        remaining: List[str] = []
        expected_side_effects: List[str] = []
        regressions: List[str] = []
        for key in sorted(set(before) & set(after)):
            if key in cls.CRITICAL_CONDITIONS:
                if before[key] < 1.0 <= after[key]:
                    recovered.append(key)
                if after[key] < 1.0:
                    remaining.append(key)
            direction = directions.get(key)
            if direction == "lower_is_better" and after[key] > before[key]:
                if key in cls.EXPECTED_RECOVERY_OVERHEAD:
                    expected_side_effects.append(f"{key}_increase")
                else:
                    regressions.append(key)
            elif direction == "higher_is_better" and after[key] < before[key]:
                regressions.append(key)

        return {
            "status": str(result.get("status") or "inconclusive").lower(),
            "confidence": float(result.get("confidence") or 0.0),
            "before": before,
            "after": after,
            "changes": cls._sanitize_value(result.get("changes") or []),
            "recovered_signals": recovered,
            "remaining_symptoms": remaining,
            "expected_side_effects": expected_side_effects,
            "unexpected_regressions": regressions,
            "evidence_refs": cls._dedupe_strings(result.get("evidence_refs") or []),
            "message": cls._sanitize_string(str(result.get("message") or "")),
        }

    @classmethod
    def _actual_remediation(
        cls,
        *,
        execution_request: Dict[str, Any],
        execution_result: Dict[str, Any],
        approval: Dict[str, Any],
        service: str,
    ) -> Dict[str, Any]:
        parameters = cls._sanitize_value(execution_request.get("parameters") or {})
        bound_service = (
            parameters.get("service") if isinstance(parameters, dict) else None
        ) or service
        return {
            "tool_name": execution_result.get("tool_name") or execution_request.get("tool_name"),
            "action": execution_result.get("action") or execution_request.get("action"),
            "target": execution_result.get("target") or execution_request.get("target"),
            "parameters": parameters,
            "service": bound_service,
            "runbook_id": execution_request.get("runbook_id"),
            "runbook_version": execution_request.get("runbook_version"),
            "approval_required": bool(approval or execution_request.get("approval_id")),
            "approval_id": (
                execution_result.get("approval_id")
                or execution_request.get("approval_id")
                or approval.get("approval_id")
            ),
            "execution_success": (
                bool(execution_result.get("success")) if execution_result else None
            ),
            "execution_blocked": (
                bool(execution_result.get("execution_blocked")) if execution_result else False
            ),
            "execution_error_class": cls._error_class(
                execution_result.get("error") or execution_result.get("reason")
            ),
            "execution_duration": execution_result.get("execution_time"),
        }

    @staticmethod
    def _error_class(value: Any) -> Optional[str]:
        text_value = str(value or "").strip()
        return text_value.split(":", 1)[0][:120] if text_value else None

    @staticmethod
    def _outcome_class(
        execution: Dict[str, Any], verification: Dict[str, Any], state: Dict[str, Any]
    ) -> str:
        status = str(verification.get("status") or "").lower()
        if execution:
            if execution.get("execution_blocked"):
                return "execution_blocked"
            if not execution.get("success"):
                return "failed_recovery"
            if status == "success":
                return "successful_recovery"
            if status == "partial":
                return "partial_recovery"
            if status == "failed":
                return "failed_recovery"
            return "diagnostic_only"
        if status == "success":
            return "self_recovered"
        if str(state.get("terminal_reason") or "").lower() == "false_positive":
            return "false_positive"
        return "diagnostic_only"

    @classmethod
    def _investigation_summary(
        cls,
        *,
        triage: Dict[str, Any],
        coordination: Dict[str, Any],
        findings: List[Dict[str, Any]],
    ) -> str:
        parts: List[str] = []
        for value in (
            coordination.get("summary"),
            coordination.get("statement"),
            triage.get("summary"),
            triage.get("likely_cause"),
        ):
            text_value = str(value or "").strip()
            if text_value and text_value not in parts:
                parts.append(text_value)
        for finding in sorted(
            findings,
            key=lambda item: float(item.get("confidence") or 0.0),
            reverse=True,
        )[:5]:
            statement = str(
                finding.get("statement") or finding.get("summary") or ""
            ).strip()
            if statement and statement not in parts:
                parts.append(statement)
        if not parts:
            return "No durable investigation summary was produced."
        return cls._sanitize_string(" | ".join(parts))

    @classmethod
    def _specialist_findings(
        cls,
        findings: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        values: List[Dict[str, Any]] = []
        for finding in findings[:50]:
            values.append(
                cls._sanitize_value(
                    {
                        "agent": finding.get("agent_name") or finding.get("agent"),
                        "statement": finding.get("statement") or finding.get("summary"),
                        "confidence": finding.get("confidence"),
                        "severity": finding.get("severity"),
                        "health_status": finding.get("health_status"),
                        "evidence_ids": finding.get("evidence_ids") or [],
                        "supporting_evidence_ids": finding.get("supporting_evidence_ids") or [],
                        "conflicting_evidence_ids": finding.get("conflicting_evidence_ids") or [],
                        "missing_evidence": finding.get("missing_evidence") or [],
                        "recommended_checks": finding.get("recommended_checks") or [],
                        "hypotheses": finding.get("hypotheses") or [],
                    }
                )
            )
        return values

    @classmethod
    def _evidence_requests(
        cls,
        findings: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        requests: List[Dict[str, Any]] = []
        seen: set[str] = set()
        for finding in findings:
            agent = str(finding.get("agent_name") or finding.get("agent") or "")
            for request in finding.get("evidence_requests") or []:
                if not isinstance(request, dict):
                    continue
                clean = cls._sanitize_value(
                    {
                        "agent": agent,
                        "evidence_type": request.get("evidence_type"),
                        "reason": request.get("reason"),
                        "preferred_source": request.get("preferred_source"),
                    }
                )
                signature = cls._stable_text(clean)
                if signature in seen:
                    continue
                seen.add(signature)
                requests.append(clean)
                if len(requests) >= 100:
                    return requests
        return requests

    @staticmethod
    def _hypotheses(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        values: List[Dict[str, Any]] = []
        for finding in findings:
            statement = finding.get("statement") or finding.get("summary")
            if statement:
                values.append({
                    "agent": finding.get("agent_name") or finding.get("agent"),
                    "statement": statement,
                    "confidence": finding.get("confidence"),
                    "evidence_ids": finding.get("evidence_ids") or [],
                })
        return values[:50]

    @staticmethod
    def _causal_factors(findings: List[Dict[str, Any]]) -> List[Any]:
        factors: List[Any] = []
        for finding in findings:
            details = finding.get("analysis_details")
            if isinstance(details, dict) and isinstance(details.get("causal_factors"), list):
                factors.extend(details["causal_factors"])
        return factors[:50]

    @staticmethod
    def _contributing_factors(findings: List[Dict[str, Any]]) -> List[Any]:
        factors: List[Any] = []
        for finding in findings:
            details = finding.get("analysis_details")
            if isinstance(details, dict) and isinstance(details.get("contributing_factors"), list):
                factors.extend(details["contributing_factors"])
        return factors[:50]

    @classmethod
    def _evidence_items(cls, state: Dict[str, Any]) -> List[Dict[str, Any]]:
        context = dict(state.get("context") or {})
        raw = context.get("evidence")
        if not isinstance(raw, list):
            live = state.get("live_evidence") or context.get("live_evidence") or {}
            raw = live.get("evidence", []) if isinstance(live, dict) else []
        return [item for item in raw if isinstance(item, dict)][:200]

    @classmethod
    def _evidence_refs(
        cls,
        state: Dict[str, Any],
        evidence: List[Dict[str, Any]],
        verification: Dict[str, Any],
    ) -> List[str]:
        refs = [
            str(item.get("reference") or item.get("evidence_id") or item.get("id") or "")
            for item in evidence
        ]
        for finding in state.get("findings", []) or []:
            if isinstance(finding, dict):
                refs.extend(str(ref) for ref in finding.get("evidence_ids", []) if ref)
        refs.extend(str(ref) for ref in verification.get("evidence_refs", []) if ref)
        return cls._dedupe_strings(refs)

    @classmethod
    def _reusable_lesson(
        cls,
        *,
        service: str,
        root_cause_status: str,
        actual_remediation: Dict[str, Any],
        verification: Dict[str, Any],
        outcome_class: str,
    ) -> str:
        action = str(actual_remediation.get("action") or "no governed action")
        recovered = ", ".join(verification.get("recovered_signals") or []) or "no verified recovery signals"
        if outcome_class == "successful_recovery":
            return (
                f"For this historical {service} symptom pattern, {action} restored availability "
                f"and verification recovered: {recovered}. Historical root cause status is "
                f"{root_cause_status}; revalidate current live evidence and execution preconditions before reuse."
            )
        if outcome_class in {"failed_recovery", "partial_recovery"}:
            return (
                f"For this historical {service} symptom pattern, {action} produced outcome "
                f"{outcome_class}. Treat the previous action as cautionary experience, not a default recommendation; "
                "re-investigate current live evidence before proposing remediation."
            )
        if outcome_class == "execution_blocked":
            return (
                f"A governed action for historical {service} symptoms was blocked by current policy/preconditions. "
                "Do not infer that the action is safe or effective from this episode."
            )
        return (
            f"Historical {service} investigation was recorded as {outcome_class}. "
            "Use it only as auxiliary investigation context and validate all current operational claims from live evidence."
        )

    @classmethod
    def _episode_fingerprint(cls, episode: Dict[str, Any]) -> str:
        remediation = dict(episode.get("actual_remediation") or {})
        verification = dict(episode.get("verification") or {})
        identity = {
            "incident_id": str(episode.get("incident_id") or ""),
            "service_scope": episode.get("service_scope"),
            "environment": episode.get("environment"),
            "remediation": {
                "tool_name": remediation.get("tool_name"),
                "action": remediation.get("action"),
                "target": remediation.get("target"),
                "service": remediation.get("service"),
                "runbook_id": remediation.get("runbook_id"),
                "runbook_version": remediation.get("runbook_version"),
                "approval_id": remediation.get("approval_id"),
                "execution_success": remediation.get("execution_success"),
                "execution_blocked": remediation.get("execution_blocked"),
            },
            "verification": {
                "status": verification.get("status"),
                "before": verification.get("before"),
                "after": verification.get("after"),
            },
            "memory_outcome_class": episode.get("memory_outcome_class"),
        }
        return cls._signature(identity)

    @classmethod
    def _search_document(cls, episode: Dict[str, Any]) -> str:
        values = [
            episode.get("service_scope"),
            episode.get("asset_type"),
            episode.get("asset_id"),
            episode.get("hostname"),
            episode.get("fqdn"),
            episode.get("platform"),
            episode.get("pattern"),
            episode.get("normalized_symptoms"),
            episode.get("investigation"),
            episode.get("root_cause"),
            episode.get("root_cause_status"),
            episode.get("actual_remediation"),
            episode.get("memory_outcome_class"),
            episode.get("reusable_lesson"),
        ]
        return " ".join(
            cls._stable_text(value)
            for value in values
            if value not in (None, "", [], {})
        )[:16000]

    @classmethod
    def _sanitize_value(cls, value: Any, *, depth: int = 0) -> Any:
        if depth > 6:
            return "[TRUNCATED]"
        if value is None or isinstance(value, (bool, int, float)):
            return value
        if isinstance(value, datetime):
            return value.isoformat()
        if isinstance(value, str):
            return cls._sanitize_string(value)
        if isinstance(value, dict):
            result: Dict[str, Any] = {}
            for key, item in list(value.items())[:100]:
                normalized_key = str(key)
                if cls._is_sensitive_key(normalized_key):
                    result[normalized_key] = "[REDACTED]"
                else:
                    result[normalized_key] = cls._sanitize_value(item, depth=depth + 1)
            return result
        if isinstance(value, (list, tuple, set)):
            return [
                cls._sanitize_value(item, depth=depth + 1)
                for item in list(value)[:100]
            ]
        return cls._sanitize_string(str(value))

    @classmethod
    def _is_sensitive_key(cls, key: str) -> bool:
        normalized = re.sub(r"[^a-z0-9]+", "_", str(key or "").strip().lower()).strip("_")
        if normalized in cls.SECRET_KEYS:
            return True
        tokens = [token for token in normalized.split("_") if token]
        sensitive_tokens = {
            "password", "passwd", "pwd", "secret", "token", "apikey",
            "authorization", "cookie", "privatekey", "clientsecret",
        }
        if any(token in sensitive_tokens for token in tokens):
            return True
        suffixes = (
            "_password", "_passwd", "_pwd", "_secret", "_token", "_api_key",
            "_apikey", "_authorization", "_cookie", "_private_key",
            "_client_secret", "_access_token", "_refresh_token", "_id_token",
        )
        return normalized.endswith(suffixes)

    @classmethod
    def _sanitize_string(cls, value: str) -> str:
        text_value = str(value or "")
        for pattern in cls.SECRET_PATTERNS:
            text_value = pattern.sub(
                lambda match: f"{match.group(1)}: [REDACTED]",
                text_value,
            )
        return text_value[:8000]

    @staticmethod
    def _stable_text(value: Any) -> str:
        if isinstance(value, str):
            return value
        return json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            default=str,
            separators=(",", ":"),
        )

    @classmethod
    def _signature(cls, value: Any) -> str:
        clean = cls._sanitize_value(value)
        return hashlib.sha256(cls._stable_text(clean).encode("utf-8")).hexdigest()

    @staticmethod
    def _dedupe_strings(values: Iterable[Any]) -> List[str]:
        return list(
            dict.fromkeys(str(value) for value in values if str(value).strip())
        )[:200]
