"""Read-only, versioned Incident Decision Brief assembled from durable observations.

Neither retrieval nor rendering calls MCP, Cognia, LLM, approval or execution.
Unproven causal links are explicitly unknown. This module is not an authority gate.
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any, Iterable

from domain.contracts.redaction import redact

CONTRACT_VERSION = "decision-brief.v1"
FRESHNESS_SECONDS = 900  # UI warning threshold, not an execution policy


def obj(value: Any) -> dict:
    return value if isinstance(value, dict) else {}


def arr(value: Any) -> list:
    return value if isinstance(value, list) else []


def safe(value: Any, limit: int = 800) -> str | None:
    if value is None:
        return None
    result = str(redact(value))
    return result[:limit] + ("…" if len(result) > limit else "")


def numeric(value: Any) -> float | None:
    try:
        score = float(value)
        return score if 0 <= score <= 1 else None
    except (TypeError, ValueError):
        return None


def refs(value: Any) -> list[str]:
    return [safe(x, 180) for x in arr(value)[:30] if isinstance(x, (str, int)) and str(x)]


def freshness(value: Any, now: datetime) -> str:
    if not value:
        return "unknown"
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            return "unknown"
        age = (now - parsed.astimezone(timezone.utc)).total_seconds()
        return "fresh" if -60 <= age <= FRESHNESS_SECONDS else "stale"
    except (TypeError, ValueError, OverflowError):
        return "unknown"


def tool_failed(record: dict) -> bool:
    """HTTP 200 alone does not prove nested tool success."""
    if record.get("success") is False or record.get("ok") is False:
        return True
    if str(record.get("status") or "").lower() in {"error", "failed", "timeout", "unavailable", "blocked"}:
        return True
    if record.get("error") not in (None, "", False):
        return True
    for key in ("result", "tool_result", "response"):
        nested = record.get(key)
        if isinstance(nested, dict) and tool_failed(nested):
            return True
    return False


def _agents(state: dict, findings: Iterable[dict]) -> list[dict]:
    results = []
    triage = obj(state.get("triage_result"))
    if triage:
        results.append(triage)
    results.extend(x for x in arr(state.get("analysis_results")) if isinstance(x, dict))
    # Durable findings from earlier/legacy incidents have no proven run result.
    if not results:
        results = [dict(x, _legacy_finding=True) for x in findings if isinstance(x, dict)]
    items = []
    for result in results[:35]:
        details = obj(result.get("analysis_details"))
        conflict_refs = refs(result.get("conflicting_evidence_ids"))
        missing = [safe(x, 250) for x in arr(result.get("missing_evidence"))[:15]]
        failed = bool(details.get("error")) or str(result.get("finding_type") or "").endswith("_error")
        status = ("unknown" if result.get("_legacy_finding") else
                  "failed" if failed else "partial" if missing or conflict_refs else "success")
        items.append({
            "agent": safe(result.get("agent_name") or result.get("agent") or "unknown", 90),
            "status": status,
            "finding": safe(result.get("statement") or result.get("finding_type")),
            "confidence": numeric(result.get("confidence")),
            "evidence_refs": refs(result.get("evidence_ids")),
            "conflicting_evidence_refs": conflict_refs,
            "missing_evidence": missing,
            "historical_memory_ids": refs(result.get("historical_memory_ids")),
            "knowledge_source_ids": refs(result.get("knowledge_source_ids")),
        })
    return items


def _mcp(rows: Iterable[dict], now: datetime) -> tuple[list[dict], list[dict]]:
    items = []
    sources = {}
    for item in rows:
        if not isinstance(item, dict):
            continue
        raw = obj(item.get("raw_data"))
        origin = str(item.get("source") or "")
        observation_status = str(raw.get("status") or "").lower()
        # EvidenceCollector records provider outage/empty-query status as a
        # source_observation; the Incident repository stores it under type=event.
        # Identify it by the canonical result_count/status shape, not HTTP 200.
        is_source_observation = (
            "result_count" in raw
            and observation_status in {"queried", "unavailable", "error", "skipped"}
            and origin.lower() in {"prometheus", "elasticsearch", "zabbix", "vm_mcp"}
        )
        mcp = raw.get("mcp_server") or raw.get("server") or (
            origin if "mcp" in origin.lower() or is_source_observation else None
        )
        explicit_time = raw.get("collected_at") or raw.get("observed_at") or raw.get("timestamp")
        collected = explicit_time or item.get("created_at")
        age = freshness(collected, now)
        source_name = safe(mcp or origin, 160) or "unknown"
        if source_name not in sources:
            sources[source_name] = {
                "source": source_name,
                "freshness": age,
                "status": observation_status if is_source_observation else "observed",
            }
        if mcp is None:
            continue
        inner = obj(raw.get("tool_result") or raw.get("result"))
        explicit_success = raw.get("success") is True or inner.get("success") is True
        status = (
            "failed" if is_source_observation and observation_status in {"unavailable", "error"} else
            observation_status if is_source_observation else
            "failed" if tool_failed(raw) else
            "success" if explicit_success else "unknown"
        )
        items.append({
            "evidence_ref": safe(item.get("id") or item.get("evidence_id") or item.get("reference"), 180),
            "server": source_name,
            "tool": safe(raw.get("tool_name") or raw.get("tool") or raw.get("diagnostic"), 120)
                    or ("source_observation" if is_source_observation else None),
            "status": status,
            "collected_at": safe(collected, 55),
            "time_basis": "source_observed" if explicit_time else "evidence_persisted",
            "freshness": age,
            "phase": safe(raw.get("phase") or raw.get("collection_phase"), 70) or "unknown",
            "finding": safe(raw.get("summary") or raw.get("message") or raw.get("detail") or raw.get("diagnostic"), 380),
        })
    return items[:100], list(sources.values())[:50]


def _knowledge(state: dict, agents: list[dict]) -> dict:
    retrieval = obj(state.get("knowledge_status"))
    documents = arr(state.get("knowledge_results"))
    cited = {ref for a in agents for ref in a["knowledge_source_ids"]}
    entries = []
    for doc in documents[:30]:
        if not isinstance(doc, dict):
            continue
        source_id = safe(doc.get("source_id") or doc.get("id"), 200)
        entries.append({
            "source_id": source_id,
            "knowledge_base_id": safe(doc.get("knowledge_base_id"), 90),
            "knowledge_id": safe(doc.get("knowledge_id"), 90),
            "revision_id": safe(doc.get("revision_id"), 90),
            "relevance": numeric(doc.get("relevance")),
            "excerpt": safe(doc.get("content"), 450),
            "retrieved_at": safe(doc.get("retrieved_at"), 55),
            "use_status": "cited_by_agent" if source_id and source_id in cited else "not_verified",
        })
    status = str(retrieval.get("status") or "not_queried").lower()
    if status not in {"available", "empty", "not_queried"}:
        status = "failed"
    return {
        "status": status,
        "retrieved_count": len(documents),
        "use_status": "cited_by_agent" if any(d["use_status"] == "cited_by_agent" for d in entries) else "not_verified",
        "items": entries,
        "error_code": safe(retrieval.get("code"), 100),
    }


def _memory(state: dict, agents: list[dict]) -> dict:
    cited = {ref for a in agents for ref in a["historical_memory_ids"]}
    items = []
    for memory in arr(state.get("memory_results"))[:20]:
        if not isinstance(memory, dict):
            continue
        mid = safe(memory.get("id") or memory.get("memory_id"), 180)
        items.append({
            "memory_id": mid,
            "previous_incident_id": safe(memory.get("incident_id"), 180),
            "root_cause": safe(memory.get("root_cause"), 350),
            "action": safe(memory.get("action"), 350),
            "outcome": safe(memory.get("memory_outcome_class") or memory.get("outcome"), 100),
            "verification": safe(memory.get("verification_result"), 100),
            "similarity": numeric(memory.get("vector_similarity")),
            "use_status": "cited_by_agent" if mid and mid in cited else "not_verified",
        })
    return {"items": items, "retrieved_count": len(arr(state.get("memory_results"))), "historical_not_current_evidence": True}


def build_decision_brief(
    *,
    incident: dict,
    operator_summary: dict,
    checkpoint: dict,
    durable_evidence: Iterable[dict],
    findings: Iterable[dict],
    audit_events: Iterable[dict],
    knowledge_review: dict | None = None,
    now: datetime | None = None,
) -> dict:
    now = now or datetime.now(timezone.utc)
    state = obj(checkpoint.get("state"))
    summary = obj(operator_summary)
    evidence = [e for e in durable_evidence if isinstance(e, dict)]
    agents = _agents(state, findings)
    mcp, sources = _mcp(evidence, now)
    knowledge = _knowledge(state, agents)
    memory = _memory(state, agents)
    approval = obj(summary.get("approval"))
    observed = obj(summary.get("observed_state"))
    recommendation = obj(summary.get("recommended_action"))
    verification = obj(summary.get("verification"))
    execution = obj(summary.get("execution"))
    decision = obj(state.get("decision"))
    evaluation = obj(state.get("evaluation"))
    coordination = obj(state.get("coordination"))
    conflict_refs = sorted({r for a in agents for r in a["conflicting_evidence_refs"]})
    missing = sorted({r for a in agents for r in a["missing_evidence"]})
    monitor_error = obj(state.get("live_evidence")).get("error")
    if monitor_error:
        missing.append("live_evidence_collection_failed")
    if not evidence:
        missing.append("no_durable_evidence")
    freshnesses = [freshness(e.get("created_at"), now) for e in evidence]
    data_freshness = (
        "unknown" if not freshnesses or all(x == "unknown" for x in freshnesses)
        else "mixed" if "fresh" in freshnesses and ("stale" in freshnesses or "unknown" in freshnesses)
        else "stale" if "stale" in freshnesses
        else "fresh" if all(x == "fresh" for x in freshnesses)
        else "unknown"
    )
    risk = safe(summary.get("risk_level"), 40) or "unknown"
    service = safe(incident.get("service"), 120) or "نامشخص"
    decision_state = safe(decision.get("decision"), 90) or "unknown"
    result_fa = (
        f"رخداد سرویس «{service}» در وضعیت {safe(incident.get('status'), 50) or 'نامشخص'} قرار دارد. "
        f"{len(evidence)} رکورد شواهد ثبت شده است؛ اعتبار زمانی شواهد: "
        f"{'تازه' if data_freshness == 'fresh' else 'قدیمی' if data_freshness == 'stale' else 'نامشخص'}. "
        f"وضعیت دانش Cognia: {knowledge['status']}؛ {knowledge['retrieved_count']} نتیجه بازیابی شده است. "
        "استفاده از دانش و تجربه تاریخی فقط در صورت وجود استناد مستقل قابل تأیید است. "
        f"ریسک اقدام: {risk}؛ وضعیت تأیید: {approval.get('status') or 'ثبت نشده'}. "
        "پیش از تصمیم، هدف، ابزار، شواهد ناقص و برنامه Verification را بررسی کنید."
    )
    result_en = (
        f"Incident affecting {safe(incident.get('service'), 120) or 'unknown service'}; "
        f"status: {safe(incident.get('status'), 50) or 'unknown'}. "
        f"{len(evidence)} durable evidence records; freshness: {data_freshness}. "
        f"Cognia: {knowledge['status']} ({knowledge['retrieved_count']} retrieved); "
        "retrieval does not prove use in the decision. "
        f"Action risk: {risk}; approval: {approval.get('status') or 'not requested'}. "
        "Review the bound target, tool, missing evidence and verification plan before deciding."
    )
    timeline = [
        {
            "event": safe(row.get("event_type"), 120),
            "status": safe(row.get("status"), 60),
            "actor": safe(row.get("actor"), 100),
            "timestamp": safe(row.get("created_at"), 55),
            "event_id": safe(row.get("event_id"), 180),
        }
        for row in audit_events if isinstance(row, dict)
    ][:100]
    recorded = {
        "incident_summary": {
            "incident_id": safe(incident.get("id"), 180),
            "service": service, "severity": safe(incident.get("severity"), 40),
            "status": safe(incident.get("status"), 50),
            "started_at": safe(incident.get("started_at"), 55),
            "target": safe(observed.get("target"), 180),
            "port": observed.get("port"),
            "target_source": safe(obj(observed.get("field_sources")).get("target"), 90),
            "observed_service_state": redact({
                key: observed.get(key) for key in (
                    "service_status", "process_status", "port_listener_status",
                    "tcp_check", "config_validate",
                ) if observed.get(key) is not None
            }),
            "summary": safe(incident.get("summary"), 450),
            "likely_cause": safe(summary.get("likely_cause"), 420),
            "cause_status": safe(summary.get("cause_confidence"), 40),
            "cause_evidence_refs": refs(summary.get("cause_evidence_ids")),
        },
        "agent_findings": agents,
        "mcp_evidence": mcp,
        "monitoring_sources": sources,
        "timeline": timeline,
        "cognia_knowledge": knowledge,
        "operational_memory": memory,
        "rca_assessment": {
            "rca_confidence": numeric(state.get("confidence")),
            "evaluator_confidence": numeric(evaluation.get("confidence")),
            "agent_agreement": numeric(coordination.get("agreement_score")),
            "note": "RCA, evaluator and agent agreement are independent measurements; absent values are unknown.",
        },
        "evidence_conflicts": conflict_refs,
        "missing_evidence": missing,
        "remediation_recommendation": {
            "action": safe(recommendation.get("action") or approval.get("action"), 120),
            "tool": safe(recommendation.get("tool") or approval.get("tool"), 120),
            "target": safe(recommendation.get("target") or approval.get("target"), 180),
            "risk_level": risk,
            "decision": decision_state,
            "why": "مبنای پیشنهاد در یافته‌ها و تصمیم ذخیره‌شده است؛ ارتباط علّی تأییدنشده را قطعی تلقی نکنید.",
            "unverified_assumptions": missing,
            "blast_radius": safe(decision.get("blast_radius"), 150),
            "risk_of_inaction": safe(decision.get("risk_of_inaction"), 250),
            "expected_outcome": safe(decision.get("expected_outcome"), 250),
            "verification_plan": safe(state.get("verification_plan"), 350),
        },
        "approval_readiness": {
            "status": "human_review_required" if approval.get("status") == "pending" else "not_pending",
            "approval_id": safe(approval.get("approval_id"), 180),
            "approval_status": safe(approval.get("status"), 60),
            "binding_complete": approval.get("binding_complete") is True,
            "tool": safe(approval.get("tool"), 120),
            "action": safe(approval.get("action"), 120),
            "target": safe(approval.get("target"), 180),
            "environment": safe(approval.get("environment"), 90),
            "runbook_id": safe(approval.get("runbook_id"), 90),
            "runbook_version": safe(approval.get("runbook_version"), 90),
            "binding_version": approval.get("binding_version"),
            "binding_digest": safe(approval.get("binding_digest"), 130),
            "rollback_supported": approval.get("rollback_supported") is True,
            "timeout_seconds": approval.get("timeout_seconds"),
            "evidence_snapshot_binding": "not_verified",
            "data_freshness": data_freshness,
            "warning": "A report never authorizes execution. Approval and one-time workflow resume remain mandatory.",
        },
        "execution_outcome": {
            "status": safe(summary.get("execution_status"), 60),
            "tool": safe(execution.get("tool"), 120),
            "action": safe(execution.get("action"), 120),
            "target": safe(execution.get("target"), 180),
            "error": safe(execution.get("error"), 280),
        },
        "verification_result": {
            "status": safe(summary.get("verification_status"), 60),
            "message": safe(verification.get("message"), 350),
            "evidence_refs": refs(verification.get("evidence_refs")),
        },
        "knowledge_learning_status": {
            "memory_id": safe(obj(summary.get("memory")).get("memory_entry_id"), 180),
            "review_id": safe(obj(knowledge_review).get("id"), 180),
            "review_status": safe(obj(knowledge_review).get("status"), 80),
            "review_available": (
                str(summary.get("verification_status")).lower() in {"success", "verified", "succeeded"}
                and bool(obj(summary.get("memory")).get("memory_entry_id"))
                and bool(obj(knowledge_review).get("id"))
            ),
        },
        "localized_narrative": {
            "fa": result_fa, "en": result_en,
            "generator": "deterministic_fallback",
            "llm_used": False,
        },
        "data_freshness": data_freshness,
        "source_references": sorted({
            safe(e.get("id") or e.get("evidence_id"), 180)
            for e in evidence if e.get("id") or e.get("evidence_id")
        }),
        "checkpoint_version": checkpoint.get("version"),
    }
    # Snapshot fingerprint excludes generated_at; the same durable state produces
    # the same binding for audit and staleness inspection, never authorization.
    canonical = json.dumps(redact(recorded), sort_keys=True, ensure_ascii=False, default=str)
    snapshot = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    return {
        "contract_version": CONTRACT_VERSION,
        "snapshot_id": snapshot,
        "generated_at": now.isoformat(),
        **redact(recorded),
        "source_policy": {"durable_only": True, "read_only": True, "authorizes_execution": False},
    }
