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
from agents.storage.engine import correlate_disk_file_causality
from apps.technical_investigation_report import build_technical_investigation

CONTRACT_VERSION = "decision-brief.v1"
FRESHNESS_SECONDS = 900  # UI warning threshold, not an execution policy

_FA_STATUS = {
    "open": "باز", "analyzing": "در حال تحلیل", "resolved": "رفع شده",
    "closed": "بسته شده", "escalated": "ارجاع شده",
    "pending": "در انتظار تأیید", "approved": "تأیید شده",
    "rejected": "رد شده", "consumed": "مصرف شده",
    "available": "در دسترس", "empty": "بدون نتیجه",
    "failed": "ناموفق", "not_queried": "جست‌وجو نشده",
    "unknown": "نامشخص", "low": "کم", "medium": "متوسط",
    "high": "زیاد", "critical": "بحرانی",
    "confirmed": "تأیید شده", "probable": "محتمل",
}


def fa_status(value: Any) -> str:
    key = str(value or "unknown").lower()
    return _FA_STATUS.get(key, "نامشخص")



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



def operator_presentation_context(
    incident: dict, state: dict, evidence: list[dict], summary: dict,
) -> dict:
    """Explain missing execution fields without assigning execution authority.

    Direct observations are read from attributed, successful VM MCP records;
    historical Agent prose, alert titles, and guessed runtime are excluded.
    This presentation metadata is intentionally outside the approval snapshot.
    """
    service = str(incident.get("service") or "").lower().removesuffix(".service")
    observed_host = str(obj(summary.get("observed_state")).get("target") or "")
    context = obj(incident.get("context"))
    trigger = obj(context.get("trigger_signal"))
    signal = obj(trigger.get("payload") or trigger)
    declared_host = str(signal.get("target_ip") or signal.get("host_ip") or "")
    # Never mix service evidence from different VMs. An unexplained
    # discrepancy disables attributed observations instead of choosing one.
    conflict = bool(observed_host and declared_host and observed_host != declared_host)
    host = "" if conflict else observed_host or declared_host
    platform = str(signal.get("platform") or signal.get("asset_type") or "").lower()
    collected = []
    for row in ([] if conflict or not host else evidence):
        raw = obj(row.get("raw_data"))
        if row.get("source") != "vm_mcp" or raw.get("success") is not True:
            continue
        if str(raw.get("service") or "").lower().removesuffix(".service") != service:
            continue
        if host and str(raw.get("target") or "") != host:
            continue
        diagnostic = str(raw.get("diagnostic") or raw.get("tool_name") or "")
        if diagnostic not in {"service_status", "process_status", "dotnet_config_syntax",
                              "config_validate", "disk_status", "port_listener_status",
                              "service_runtime_discovery"}:
            continue
        keys = {
            "service_status": ("active_state", "sub_state", "result", "main_pid"),
            "process_status": ("running", "count"),
            "dotnet_config_syntax": ("syntax_valid", "validated_scope"),
            "config_validate": ("supported", "valid"),
            "disk_status": ("used_percent", "free_bytes", "mount"),
            "port_listener_status": ("listening", "target_port"),
            "service_runtime_discovery": ("runtime", "entrypoint", "unit_file"),
        }[diagnostic]
        values = {key: raw[key] for key in keys
                  if isinstance(raw.get(key), (str, int, float, bool))}
        if values:
            collected.append({
                "diagnostic": diagnostic,
                "values": values, "source": "vm_mcp",
                "observed_at": safe(row.get("created_at"), 50),
                "evidence_ref": safe(row.get("reference") or row.get("id"), 160),
            })
    # Newest per diagnostic; no fabricated metrics for absent tools.
    latest = {}
    for item in sorted(collected, key=lambda x: str(x.get("observed_at") or "")):
        latest[item["diagnostic"]] = item
    execution = obj(state.get("execution_request"))
    approval = obj(summary.get("approval"))
    evaluation = obj(state.get("evaluation"))
    has_action = bool(execution.get("action") or approval.get("action"))
    decision = obj(state.get("decision"))
    terminal = str(state.get("terminal_reason") or "")
    blocked = bool(
        not has_action and (
            terminal or evaluation.get("approved_for_decision") is False
            or str(decision.get("action") or "").lower() in {"block", "escalate"}
        )
    )
    return {
        "service": service,
        "host": host or None,
        "platform": "vm_systemd" if platform in {"vm", "linux_vm"} or "service_status" in latest
                    else "kubernetes" if platform in {"kubernetes", "k8s"} else None,
        "observations": latest,
        "action_disposition": (
            "action_requested" if has_action else
            "blocked_by_evaluator" if blocked else "no_action_proposed"
        ),
        "block_reason": safe(terminal or evaluation.get("reason"), 220) if blocked else None,
        "no_action_authorized": not has_action,
        "read_only": True,
    }


def elapsed_seconds(value: Any, now: datetime) -> int | None:
    if not value:
        return None
    try:
        start = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        if start.tzinfo is None:
            return None
        return max(0, int((now - start.astimezone(timezone.utc)).total_seconds()))
    except (TypeError, ValueError, OverflowError):
        return None


def evidence_usable(item: dict, age: str) -> bool:
    raw = obj(item.get("raw_data"))
    status = str(raw.get("status") or "").lower()
    # Provider health observations (including successful empty queries) are
    # useful diagnostics, not evidence confirming the service state.
    is_observation = "result_count" in raw and status in {
        "queried", "unavailable", "error", "skipped",
    }
    return age == "fresh" and not is_observation and not tool_failed(raw)


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
        explicit_status = str(result.get("status") or "").lower()
        status = ("unknown" if result.get("_legacy_finding") else
                  "failed" if failed or explicit_status in {"failed", "error", "timeout"} else
                  "skipped" if explicit_status == "skipped" else
                  "partial" if explicit_status == "partial" or missing or conflict_refs else
                  "success" if explicit_status in {"success", "completed"} or result.get("statement") else "unknown")
        # Preserve each specialist's OWN output. The previous brief exposed
        # only a generic statement, making unrelated agents look identical.
        # These items are interpretations and proposed checks, NOT proof that
        # this agent executed any diagnostic command.
        hypotheses = []
        for hypothesis in arr(result.get("hypotheses"))[:5]:
            if not isinstance(hypothesis, dict):
                continue
            hypotheses.append({
                "text": safe(hypothesis.get("hypothesis"), 350),
                "probability": numeric(hypothesis.get("probability")),
                "evidence_refs": refs(hypothesis.get("evidence_ids"))[:8],
                "contradiction_refs": refs(hypothesis.get("conflicting_evidence_ids"))[:8],
                "falsification_checks": [
                    safe(x, 180) for x in arr(hypothesis.get("falsification_checks"))[:5]
                ],
            })
        items.append({
            "agent": safe(result.get("agent_name") or result.get("agent") or "unknown", 90),
            "status": status,
            "mission": safe(result.get("mission") or result.get("task") or details.get("objective"), 220),
            "tools": refs(result.get("tools_used") or result.get("tool_names")),
            "trace_id": safe(result.get("trace_id"), 180),
            "finding": safe(result.get("statement") or result.get("finding_type")),
            "finding_type": safe(result.get("finding_type"), 95),
            "health_status": safe(result.get("health_status"), 60),
            "confidence": numeric(result.get("confidence")),
            "evidence_count": result.get("evidence_count") if isinstance(result.get("evidence_count"), int) else None,
            "evidence_coverage": numeric(result.get("evidence_coverage")),
            "evidence_quality": numeric(result.get("evidence_quality")),
            "findings": [safe(x, 350) for x in arr(result.get("findings"))[:10] if isinstance(x, str)],
            "hypotheses": hypotheses,
            "recommended_checks": [safe(x, 240) for x in arr(result.get("recommended_checks"))[:8] if isinstance(x, str)],
            "recommendations": [safe(x, 240) for x in arr(result.get("recommendations"))[:6] if isinstance(x, str)],
            "affected_components": [safe(x, 120) for x in arr(result.get("affected_components"))[:6] if isinstance(x, str)],
            "probable_dependencies": [safe(x, 120) for x in arr(result.get("probable_dependencies"))[:6] if isinstance(x, str)],
            "analysis_at": safe(result.get("timestamp"), 55),
            "uncertainty_reason": safe(result.get("uncertainty_reason"), 280),
            "requires_human_review": result.get("requires_human_review") is True,
            "focus": [safe(x, 160) for x in arr(details.get("focus"))[:5] if isinstance(x, str)],
            "evidence_refs": refs(result.get("evidence_ids")),
            "conflicting_evidence_refs": conflict_refs,
            "missing_evidence": missing,
            "historical_memory_ids": refs(result.get("historical_memory_ids")),
            "knowledge_source_ids": refs(result.get("knowledge_source_ids")),
        })
    return items


def tool_observation_summary(raw: dict) -> str | None:
    """Only bounded, whitelisted scalar facts: never dump journals or tool JSON."""
    diagnostic = str(raw.get("diagnostic") or raw.get("tool_name") or "").lower()
    fields = {
        "service_status": ("active_state", "sub_state", "main_pid", "restart_count"),
        "process_status": ("running", "count"),
        "port_listener_status": ("supported", "listening", "target_port"),
        "tcp_check": ("supported", "reachable", "target_port"),
        "config_validate": ("supported", "valid", "config_file", "error_line", "syntax_error"),
        "collect_vm_metrics": ("name", "value"),
        "disk_status": ("used_percent", "free_bytes"),
        "service_logs": ("count", "access_mode"),
        "system_logs": ("count", "access_mode"),
    }.get(diagnostic, ())
    if diagnostic == "dotnet_config_syntax":
        files = []
        for row in arr(raw.get("files"))[:12]:
            if not isinstance(row, dict):
                continue
            name = safe(row.get("file"), 120)
            if not name:
                continue
            status = safe(row.get("status"), 40)
            line = row.get("line") if type(row.get("line")) is int else None
            column = row.get("column") if type(row.get("column")) is int else None
            code = safe(row.get("error_code") or row.get("reason"), 45)
            location = (f" line={line} column={column}" if line is not None else "")
            files.append(f"{name}: {status}{location}" + (f" ({code})" if code else ""))
        return safe("; ".join(files), 380) if files else "No .NET config JSON syntax results"
    if diagnostic == "dependency_investigation":
        observed = []
        for row in arr(raw.get("dependencies"))[:6]:
            if not isinstance(row, dict):
                continue
            endpoint = (f"{safe(row.get('kind'), 30)}:{safe(row.get('host'), 100)}:"
                        f"{row.get('port')}={safe(row.get('probe_status'), 35)}"
                        + (f"(HTTP {row.get('http_status')})"
                           if type(row.get("http_status")) is int else ""))
            # Show the structural source of the evidence, never a setting value.
            config_path = safe(row.get("config_file"), 160)
            config_key = safe(row.get("config_key"), 100)
            if config_path:
                endpoint += f" [file={config_path}"
                if config_key:
                    endpoint += f", key={config_key}"
                endpoint += "]"
            observed.append(endpoint)
        return safe(f"config_files_checked={raw.get('config_files_checked', 0)}; "
                    f"checks_executed={raw.get('checks_executed', 0)}; "
                    + ("; ".join(observed) if observed else "no_verified_dependency"), 380)
    if diagnostic == "redis_dependency_check":
        endpoints = [
            f"{safe(x.get('host'), 100)}:{x.get('port')}="
            f"{'reachable' if x.get('tcp_reachable') is True else 'unreachable' if x.get('tcp_reachable') is False else 'not_verified'}"
            for x in arr(raw.get("endpoints"))[:4] if isinstance(x, dict)
            and type(x.get("port")) is int
        ]
        status = safe(raw.get("status"), 50) or "unknown"
        count = raw.get("checked_files") if type(raw.get("checked_files")) is int else 0
        return safe(f"status={status}; verified_config_files_read={count}; TCP=" +
                    ("; ".join(endpoints) if endpoints else "no_verified_endpoint"), 380)
    if diagnostic == "source_observation" or (
        "result_count" in raw and raw.get("status") in
        {"queried", "skipped", "error", "unavailable"}
    ):
        status = safe(raw.get("status"), 40) or "unknown"
        count = raw.get("result_count")
        count_text = str(count) if type(count) is int else "not_counted"
        service = safe(raw.get("query_service") or raw.get("service"), 80)
        return safe(f"query_status={status}; result_count={count_text}" +
                    (f"; service={service}" if service else ""), 300)
    details = [
        f"{name}={safe(raw.get(name), 80)}" for name in fields
        if isinstance(raw.get(name), (str, bool, int, float))
    ]
    if details:
        return safe("; ".join(details), 380)
    return safe(raw.get("summary") or raw.get("message") or raw.get("detail") or
                raw.get("diagnostic"), 380)


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
            "semantic_result": (
                "configuration_invalid" if str(raw.get("diagnostic") or "") == "dotnet_config_syntax"
                and raw.get("syntax_valid") is False else
                "configuration_invalid" if str(raw.get("diagnostic") or "") == "config_validate"
                and raw.get("valid") is False else
                "configuration_valid_syntax_only" if str(raw.get("diagnostic") or "") == "dotnet_config_syntax"
                and raw.get("syntax_valid") is True else None
            ),
            "collected_at": safe(collected, 55),
            "time_basis": "source_observed" if explicit_time else "evidence_persisted",
            "freshness": age,
            "phase": safe(raw.get("phase") or raw.get("collection_phase"), 70) or "unknown",
            "finding": tool_observation_summary(raw),
        })
    return items[:100], list(sources.values())[:50]


def _knowledge(state: dict, agents: list[dict], incident_service: str | None = None) -> dict:
    from apps.context_service.knowledge_relevance import filter_service_knowledge
    retrieval = obj(state.get("knowledge_status"))
    raw_documents = arr(state.get("knowledge_results"))
    documents, relevance = filter_service_knowledge(
        raw_documents, expected_service=incident_service or state.get("service_name")
        or (state.get("context") or {}).get("service"),
        purpose="decision_brief",
    )
    cited = {ref for a in agents for ref in a["knowledge_source_ids"]}
    entries = []
    for doc in documents[:30]:
        if not isinstance(doc, dict):
            continue
        source_id = safe(doc.get("source_id") or doc.get("id"), 200)
        # A Cognia semantic hit is a document, not automatically a successful
        # historical incident. Only an explicit published incident marker
        # justifies labeling it as a historical experience.
        content = str(doc.get("content") or "")
        fields = {}
        allowed_fields = {
            "type", "service", "incident reference",
            "observed symptom pattern", "root cause status",
            "root cause", "approved execution action (historical)",
            "verification status", "outcome", "reusable lesson",
        }
        for line in content.splitlines()[:45]:
            name, separator, value = line.partition(":")
            key = name.strip().lower()
            if separator and key in allowed_fields and value.strip():
                fields[key] = safe(value.strip(), 240)
        kind = ("historical_incident_experience"
                if str(fields.get("type") or "").lower() == "verified incident experience"
                and fields.get("incident reference") else "knowledge_document")
        metadata = obj(doc.get("metadata"))
        declared_service = (fields.get("service") or
                            safe(metadata.get("service") or metadata.get("service_name"), 100))
        entries.append({
            "source_id": source_id,
            "knowledge_base_id": safe(doc.get("knowledge_base_id"), 90),
            "knowledge_id": safe(doc.get("knowledge_id"), 90),
            "revision_id": safe(doc.get("revision_id"), 90),
            "relevance": numeric(doc.get("relevance")),
            "excerpt": safe(doc.get("content"), 650),
            "retrieved_at": safe(doc.get("retrieved_at"), 55),
            "title": safe(doc.get("title") or doc.get("knowledge_title"), 180),
            "chunk_id": safe(doc.get("chunk_id"), 100),
            "knowledge_type": safe(doc.get("knowledge_type"), 80),
            "document_kind": kind,
            "document_service": declared_service,
            "previous_incident_id": fields.get("incident reference") if kind == "historical_incident_experience" else None,
            "symptom_pattern": fields.get("observed symptom pattern") if kind == "historical_incident_experience" else None,
            "root_cause_status": fields.get("root cause status") if kind == "historical_incident_experience" else None,
            "historical_action": fields.get("approved execution action (historical)") if kind == "historical_incident_experience" else None,
            "verification_status": fields.get("verification status") if kind == "historical_incident_experience" else None,
            "historical_outcome": fields.get("outcome") if kind == "historical_incident_experience" else None,
            "reusable_lesson": fields.get("reusable lesson") if kind == "historical_incident_experience" else None,
            "conditions": safe(doc.get("conditions"), 240),
            "use_status": "cited_by_agent" if source_id and source_id in cited else "not_verified",
            "decision_impact": "not_traced",
        })
    status = str(retrieval.get("status") or "not_queried").lower()
    if status not in {"available", "empty", "not_queried", "filtered_empty"}:
        status = "failed"
    # The final state can already be filtered by ContextBuilder/SignalAware.
    # Preserve that provenance: zero accepted is not the same as zero returned.
    upstream = obj(retrieval.get("merged_relevance") or retrieval.get("relevance"))
    rejected_count = max(
        int(relevance.get("rejected_count") or 0),
        int(upstream.get("rejected_count") or 0),
    )
    if status in {"available", "empty", "filtered_empty"}:
        status = ("available" if entries else
                  "filtered_empty" if rejected_count else "empty")
    return {
        "status": status,
        "retrieved_count": len(raw_documents),
        "accepted_count": len(entries),
        "rejected_count": rejected_count,
        "relevance": relevance,
        "rejected_examples": [
            {"source_id": safe(x.get("source_id"), 160),
             "reason": safe(x.get("reason"), 120),
             "declared_services": [safe(name, 90) for name in arr(x.get("declared_services"))[:5]]}
            for x in arr(upstream.get("rejected") or relevance.get("rejected"))[:6]
            if isinstance(x, dict)
        ],
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
            "pattern": safe(memory.get("pattern"), 300),
            "service_version": safe(memory.get("service_version"), 90),
            "asset_type": safe(memory.get("asset_type"), 90),
            "root_cause_status": safe(memory.get("root_cause_status"), 70),
            "generalization_warning": "Historical similarity does not prove current causality or safe reuse.",
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
    from apps.incident_evidence_correlation import correlate_incident_state
    correlation = correlate_incident_state(
        incident=incident, checkpoint=checkpoint, evidence=evidence,
        audit_events=audit_events, now=now,
    )
    from apps.incident_explanation import explain_incident
    explanation = explain_incident(
        evidence=evidence,
        service=incident.get("service") or state.get("service_name") or "service",
        evaluation=obj(state.get("evaluation")),
        decision=obj(state.get("decision")),
        correlation=correlation,
    )
    dotnet_config = obj(explanation.get("configuration"))
    disk_file_causality = correlate_disk_file_causality(evidence)
    from apps.incident_memory_forensics import build_memory_investigation
    memory_investigation = build_memory_investigation(
        incident=incident, checkpoint=checkpoint,
        evidence=evidence, audit_events=audit_events,
    )
    from apps.orchestrator.recovery_advice import build_vm_recovery_advisory
    # Rebuild from durable MCP observations; never trust a free-form LLM plan,
    # a model-editable checkpoint field or a historical memory as evidence.
    advisory = build_vm_recovery_advisory(
        evidence=evidence,
        service_name=incident.get("service") or state.get("service_name"),
        context=obj(state.get("context")) or obj(incident.get("context")),
    )
    knowledge = _knowledge(state, agents, incident_service=incident.get("service"))
    memory = _memory(state, agents)
    approval = obj(summary.get("approval"))
    observed = obj(summary.get("observed_state"))
    recommendation = obj(summary.get("recommended_action"))
    verification = obj(summary.get("verification"))
    execution = obj(summary.get("execution"))
    service_identity = obj(obj(state.get("context")).get("service_identity"))
    if not service_identity:
        service_identity = obj(obj(incident.get("context")).get("service_identity"))
    # Auditable, purely informational: a model/Cognia hint is never an action
    # target or evidence that a service itself caused a host-level alert.
    service_identity_display = {
        "status": safe(service_identity.get("status"), 40) or "unknown",
        "verified": service_identity.get("verified") is True,
        "basis": safe(service_identity.get("basis"), 80) or "unavailable",
        "source_host": safe(service_identity.get("source_host"), 160),
        "suspected_service": safe(service_identity.get("suspected_service"), 120),
        "suspected_service_source": safe(service_identity.get("suspected_service_source"), 60),
        "requires_more_evidence": service_identity.get("requires_more_evidence") is not False,
        "conflict_count": len(arr(service_identity.get("conflicts"))),
        "confidence": numeric(service_identity.get("confidence")),
    }
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
    for source in sources:
        if source.get("status") in {"unavailable", "error"}:
            missing.append("monitoring_source_unavailable:" + str(source["source"]))
    freshnesses = [
        freshness(obj(e.get("raw_data")).get("collected_at") or
                  obj(e.get("raw_data")).get("observed_at") or
                  obj(e.get("raw_data")).get("timestamp") or e.get("created_at"), now)
        for e in evidence
    ]
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
        f"رخداد سرویس «{service}» در وضعیت {fa_status(incident.get('status'))} قرار دارد. "
        f"{len(evidence)} رکورد شواهد ثبت شده است؛ اعتبار زمانی شواهد: "
        f"{'تازه' if data_freshness == 'fresh' else 'قدیمی' if data_freshness == 'stale' else 'ترکیبی' if data_freshness == 'mixed' else 'نامشخص'}. "
        f"وضعیت دانش Cognia: {fa_status(knowledge['status'])}؛ {knowledge['retrieved_count']} نتیجه بازیابی شده است. "
        "استفاده از دانش و تجربه تاریخی فقط در صورت وجود استناد مستقل قابل تأیید است. "
        f"وضعیت علت ریشه‌ای: {fa_status(summary.get('cause_confidence'))}. "
        f"ریسک اقدام: {fa_status(risk)}؛ وضعیت تأیید: {fa_status(approval.get('status'))}. "
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
        and str(row.get("event_type") or "") != "workflow_progress"
    ][:100]
    recorded = {
        "incident_summary": {
            "incident_id": safe(incident.get("id"), 180),
            "service_identity": service_identity_display,
            "service": service, "severity": safe(incident.get("severity"), 40),
            "status": safe(incident.get("status"), 50),
            "started_at": safe(incident.get("started_at"), 55),
            "elapsed_seconds": elapsed_seconds(incident.get("started_at"), now),
            "namespace": safe(obj(incident.get("context")).get("namespace") or obj(incident.get("context")).get("kubernetes_namespace"), 150),
            "cluster": safe(obj(incident.get("context")).get("cluster") or obj(incident.get("context")).get("cluster_name"), 150),
            "host": safe(obj(incident.get("context")).get("host") or obj(incident.get("context")).get("hostname"), 150),
            "analysis_result": safe(summary.get("likely_cause"), 300),
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
            "valid_evidence_count": sum(
                1 for row, age in zip(evidence, freshnesses) if evidence_usable(row, age)
            ),
            "total_evidence_count": len(evidence),
            "fresh_evidence_note_fa": "شواهد معتبر و تازه برای تصمیم اجرایی؛ صفر به معنی نبود همهٔ شواهد تاریخی نیست.",
            "observed_sources": len({str(row.get("source") or "")
                for row in evidence if row.get("source")}),
        },
        # A specialized .NET syntax failure takes precedence over a generic
        # config_validate "unsupported", which is NOT a successful check.
        "configuration_diagnostic": {
            "status": (
                "invalid" if dotnet_config.get("status") == "invalid" else
                "invalid" if obj(observed.get("config_validate")).get("valid") is False else
                "valid" if obj(observed.get("config_validate")).get("valid") is True else
                "json_syntax_valid" if dotnet_config.get("status") == "json_syntax_valid" else
                "unverified" if observed.get("config_validate") or dotnet_config else
                "not_checked"
            ),
            # A generic unverified path is not the file that the specialized
            # .NET checker validated. Keep checked paths independent.
            "config_file": (
                safe(dotnet_config.get("config_file"), 300) if dotnet_config
                else safe(obj(observed.get("config_validate")).get("config_file"), 300)
            ),
            "files": [
                {
                    "file": safe(row.get("file"), 140),
                    "path": safe(row.get("path"), 300),
                    "path_verified": row.get("path_verified") is True,
                    "status": safe(row.get("status"), 45),
                    "line": row.get("line") if type(row.get("line")) is int else None,
                    "column": row.get("column") if type(row.get("column")) is int else None,
                    "error_code": safe(row.get("reason"), 60),
                    "evidence_ref": safe(row.get("evidence_ref"), 180),
                }
                for row in arr(dotnet_config.get("files"))[:12]
                if isinstance(row, dict) and row.get("file")
            ],
            "root_config_file": safe(obj(observed.get("config_validate")).get("root_config_file"), 300),
            "path_source": "dotnet_config_syntax" if dotnet_config else
                           safe(obj(observed.get("config_validate")).get("config_path_source"), 80),
            "error_line": dotnet_config.get("error_line") if dotnet_config.get("status") == "invalid"
                          else obj(observed.get("config_validate")).get("error_line"),
            "error_column": dotnet_config.get("error_column") if dotnet_config else None,
            "error_code": safe(dotnet_config.get("error_code"), 60),
            "syntax_error": safe(dotnet_config.get("syntax_error_fa") or
                                 obj(observed.get("config_validate")).get("syntax_error"), 500),
            "evidence_refs": refs(dotnet_config.get("evidence_refs") or
                ([obj(observed.get("config_validate")).get("evidence_id")]
                 if obj(observed.get("config_validate")).get("evidence_id") else [])),
            "validated_scope": safe(dotnet_config.get("validated_scope"), 60),
            "remote_python_required": dotnet_config.get("remote_python_required"),
            "validator_location": safe(dotnet_config.get("validator_location"), 40),
            "repair_then_revalidate": dotnet_config.get("status") == "invalid"
                or obj(observed.get("config_validate")).get("valid") is False,
            "start_requires_valid_config_and_approval": True,
        },
        "operator_explanation": redact(explanation),
        "state_correlation": redact(correlation),
        "technical_investigation": build_technical_investigation(
            incident=incident, evidence=evidence, knowledge=knowledge,
            now=now, approval=approval,
        ),
        "memory_investigation": redact(memory_investigation) if memory_investigation else None,
        "disk_file_causality": redact(disk_file_causality) if disk_file_causality.get("files") else None,
        # Visible even when the dynamic LLM planner is disabled, and even if
        # evaluator blocks a governed execution proposal. Read-only advice.
        "recovery_advisory": redact(advisory) if advisory else None,
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
            "note": "RCA is root-cause belief; evaluator confidence assesses a proposed plan; agreement measures cross-agent consensus. Values are independent and unavailable values are not zero.",
        },
        "evidence_conflicts": conflict_refs,
        "missing_evidence": missing,
        "unknown_guidance": redact(obj(obj(state.get("context")).get("unknown_guidance"))),
        # Proposal-only; do not construct any approval or execution binding.
        # Raw file contents or unreviewed patches must never be inserted here.
        "dynamic_investigation": {
            "status": safe(obj(obj(state.get("context")).get("dynamic_investigation")).get("status"), 40)
                or "not_available",
            "model_status": safe(obj(obj(state.get("context")).get("dynamic_investigation")).get("model_status"), 45),
            "config_llm_review": {
                "status": safe(obj(obj(obj(state.get("context")).get("dynamic_investigation")).get("config_llm_review")).get("status"), 60),
                "model_validated": False,
                "vendor_validated": False,
                "model_diagnosis": {
                    "error_kind": safe(obj(obj(obj(obj(state.get("context")).get("dynamic_investigation")).get("config_llm_review")).get("model_diagnosis")).get("error_kind"), 60),
                    "line": obj(obj(obj(obj(state.get("context")).get("dynamic_investigation")).get("config_llm_review")).get("model_diagnosis")).get("line"),
                    "reason": safe(obj(obj(obj(obj(state.get("context")).get("dynamic_investigation")).get("config_llm_review")).get("model_diagnosis")).get("reason"), 350),
                    "suggestion": safe(obj(obj(obj(obj(state.get("context")).get("dynamic_investigation")).get("config_llm_review")).get("model_diagnosis")).get("suggestion"), 350),
                },
                "model_second_review": {
                    "error_kind": safe(obj(obj(obj(obj(state.get("context")).get("dynamic_investigation")).get("config_llm_review")).get("model_second_review")).get("error_kind"), 60),
                    "line": obj(obj(obj(obj(state.get("context")).get("dynamic_investigation")).get("config_llm_review")).get("model_second_review")).get("line"),
                    "reason": safe(obj(obj(obj(obj(state.get("context")).get("dynamic_investigation")).get("config_llm_review")).get("model_second_review")).get("reason"), 350),
                    "suggestion": safe(obj(obj(obj(obj(state.get("context")).get("dynamic_investigation")).get("config_llm_review")).get("model_second_review")).get("suggestion"), 350),
                },
            },
            "full_config_llm_repair": {
                "status": safe(obj(obj(obj(state.get("context")).get("dynamic_investigation")).get("full_config_llm_repair")).get("status"), 65),
                "service": safe(obj(obj(obj(state.get("context")).get("dynamic_investigation")).get("full_config_llm_repair")).get("service"), 100),
                "config_file": safe(obj(obj(obj(state.get("context")).get("dynamic_investigation")).get("full_config_llm_repair")).get("config_file"), 250),
                "source_sha256": safe(obj(obj(obj(state.get("context")).get("dynamic_investigation")).get("full_config_llm_repair")).get("source_sha256"), 64),
                "candidate_sha256": safe(obj(obj(obj(state.get("context")).get("dynamic_investigation")).get("full_config_llm_repair")).get("candidate_sha256"), 64),
                "changed_line_count": obj(obj(obj(state.get("context")).get("dynamic_investigation")).get("full_config_llm_repair")).get("changed_line_count") if type(obj(obj(obj(state.get("context")).get("dynamic_investigation")).get("full_config_llm_repair")).get("changed_line_count")) is int else 0,
                "changed_line_numbers": [
                    n for n in arr(obj(obj(obj(state.get("context")).get("dynamic_investigation")).get("full_config_llm_repair")).get("changed_line_numbers"))[:12]
                    if type(n) is int and 0 < n <= 1000000
                ],
                "llm_received_complete_file": obj(obj(obj(state.get("context")).get("dynamic_investigation")).get("full_config_llm_repair")).get("llm_received_complete_file") is True,
                "llm_returned_complete_file": obj(obj(obj(state.get("context")).get("dynamic_investigation")).get("full_config_llm_repair")).get("llm_returned_complete_file") is True,
                "candidate_returned_not_stored": obj(obj(obj(state.get("context")).get("dynamic_investigation")).get("full_config_llm_repair")).get("candidate_returned_not_stored") is True,
                "candidate_stored": obj(obj(obj(state.get("context")).get("dynamic_investigation")).get("full_config_llm_repair")).get("candidate_stored") is True,
                "validation_profile": safe(obj(obj(obj(state.get("context")).get("dynamic_investigation")).get("full_config_llm_repair")).get("validation_profile"), 35),
                "redacted_changes": [{
                    "line": x.get("line"), "before": safe(x.get("before"), 180),
                    "after": safe(x.get("after"), 180),
                } for x in arr(obj(obj(obj(state.get("context")).get("dynamic_investigation")).get("full_config_llm_repair")).get("redacted_changes"))[:12]
                  if isinstance(x, dict) and type(x.get("line")) is int],
                "rejection_reason": safe(obj(obj(obj(state.get("context")).get("dynamic_investigation")).get("full_config_llm_repair")).get("rejection_reason"), 90),
                "validation_status": "UNVERIFIED",
                "validator_executed_on_proposal": False,
                "apply_eligible": False,
                "execution_authority": False,
                "observed_at": safe(obj(obj(obj(state.get("context")).get("dynamic_investigation")).get("full_config_llm_repair")).get("observed_at"), 55),
                "source_evidence_refs": refs(obj(obj(obj(state.get("context")).get("dynamic_investigation")).get("full_config_llm_repair")).get("source_evidence_refs")),
            },
            "checks": [
                safe(x, 60)
                for x in arr(obj(obj(state.get("context")).get("dynamic_investigation")).get("checks"))[:3]
            ],
            "used_knowledge_refs": refs(
                obj(obj(state.get("context")).get("dynamic_investigation")).get("used_knowledge_refs")
            ),
            "config_discovery": {
                "service": safe(obj(obj(obj(state.get("context")).get("dynamic_investigation")).get("config_discovery")).get("service"), 100),
                "runtime": safe(obj(obj(obj(state.get("context")).get("dynamic_investigation")).get("config_discovery")).get("runtime"), 55),
                "status": safe(obj(obj(obj(state.get("context")).get("dynamic_investigation")).get("config_discovery")).get("status"), 75),
                "systemd_unit": safe(obj(obj(obj(state.get("context")).get("dynamic_investigation")).get("config_discovery")).get("systemd_unit"), 250),
                "files": [{
                    "path": safe(f.get("path"), 240),
                    "source": safe(f.get("source"), 90),
                    "verified_exists": f.get("verified_exists") is True,
                    "content_validated": False,
                } for f in arr(obj(obj(obj(state.get("context")).get("dynamic_investigation")).get("config_discovery")).get("files"))[:10]
                  if isinstance(f, dict)],
                "unverified_candidates": [{
                    "path": safe(f.get("path"), 240),
                    "source": safe(f.get("source"), 90),
                } for f in arr(obj(obj(obj(state.get("context")).get("dynamic_investigation")).get("config_discovery")).get("unverified_candidates"))[:10]
                  if isinstance(f, dict)],
                "llm_guidance_status": safe(obj(obj(obj(state.get("context")).get("dynamic_investigation")).get("config_discovery")).get("llm_guidance_status"), 60),
                "requires_further_research": obj(obj(obj(state.get("context")).get("dynamic_investigation")).get("config_discovery")).get("requires_further_research") is True,
                "execution_authority": False,
                "evidence_refs": refs(obj(obj(obj(state.get("context")).get("dynamic_investigation")).get("config_discovery")).get("evidence_refs")),
            },
            "llm_unknown_guidance": {
                "status": safe(obj(obj(obj(state.get("context")).get("dynamic_investigation")).get("llm_unknown_guidance")).get("status"), 60),
                "failure_reason": safe(obj(obj(obj(state.get("context")).get("dynamic_investigation")).get("llm_unknown_guidance")).get("failure_reason"), 80),
                "items": redact(arr(obj(obj(obj(state.get("context")).get("dynamic_investigation")).get("llm_unknown_guidance")).get("items"))[:5]),
                "execution_authority": False,
            },
            "runtime_discovery": {
                "runtime": safe(obj(obj(obj(state.get("context")).get("dynamic_investigation")).get("runtime_discovery")).get("runtime"), 50),
                "entrypoint": safe(obj(obj(obj(state.get("context")).get("dynamic_investigation")).get("runtime_discovery")).get("entrypoint"), 250),
                "publish_directory": safe(obj(obj(obj(state.get("context")).get("dynamic_investigation")).get("runtime_discovery")).get("publish_directory"), 250),
                "unit_file": safe(obj(obj(obj(state.get("context")).get("dynamic_investigation")).get("runtime_discovery")).get("unit_file"), 250),
                "service_type": safe(obj(obj(obj(state.get("context")).get("dynamic_investigation")).get("runtime_discovery")).get("service_type"), 40),
                "timeout_start_usec": safe(obj(obj(obj(state.get("context")).get("dynamic_investigation")).get("runtime_discovery")).get("timeout_start_usec"), 50),
                "runtime_evidence_ref": safe(obj(obj(obj(state.get("context")).get("dynamic_investigation")).get("runtime_discovery")).get("runtime_evidence_ref"), 160),
                "syntax_status": safe(obj(obj(obj(state.get("context")).get("dynamic_investigation")).get("runtime_discovery")).get("syntax_status"), 60),
                "syntax_valid": obj(obj(obj(state.get("context")).get("dynamic_investigation")).get("runtime_discovery")).get("syntax_valid"),
                "syntax_evidence_ref": safe(obj(obj(obj(state.get("context")).get("dynamic_investigation")).get("runtime_discovery")).get("syntax_evidence_ref"), 160),
                "files": [{
                    "file": safe(row.get("file"), 125),
                    "status": safe(row.get("status"), 45),
                    "line": row.get("line") if type(row.get("line")) is int else None,
                    "column": row.get("column") if type(row.get("column")) is int else None,
                    "error_code": safe(row.get("error_code") or row.get("reason"), 50),
                    "explanation_fa": safe(row.get("explanation_fa"), 240),
                } for row in arr(obj(obj(obj(state.get("context")).get("dynamic_investigation")).get("runtime_discovery")).get("files"))[:12]
                   if isinstance(row, dict)],
                "values_exposed": False,
                "application_ready": None,
            },
            "questions": [
                {
                    "question": safe(q.get("question"), 320),
                    "reason": safe(q.get("reason"), 250),
                    "evidence_refs": refs(q.get("evidence_refs")),
                }
                for q in arr(obj(obj(state.get("context")).get("dynamic_investigation")).get("operator_questions"))[:5]
                if isinstance(q, dict)
            ],
            "knowledge_followup": {
                "status": safe(obj(obj(obj(state.get("context")).get("dynamic_investigation")).get("knowledge_followup")).get("status"), 50),
                "query": safe(obj(obj(obj(state.get("context")).get("dynamic_investigation")).get("knowledge_followup")).get("query"), 430),
                "source_refs": refs(obj(obj(obj(state.get("context")).get("dynamic_investigation")).get("knowledge_followup")).get("source_refs")),
                "count": obj(obj(obj(state.get("context")).get("dynamic_investigation")).get("knowledge_followup")).get("count", 0),
            },
            "config_proposal": {
                "status": safe(obj(obj(obj(state.get("context")).get("dynamic_investigation")).get("config_proposal")).get("status"), 70),
                "config_file": safe(obj(obj(obj(state.get("context")).get("dynamic_investigation")).get("config_proposal")).get("config_file"), 250),
                "source_evidence_refs": refs(obj(obj(obj(state.get("context")).get("dynamic_investigation")).get("config_proposal")).get("source_evidence_refs")),
                "error_line": obj(obj(obj(state.get("context")).get("dynamic_investigation")).get("config_proposal")).get("error_line"),
                "validation_status": safe(obj(obj(obj(state.get("context")).get("dynamic_investigation")).get("config_proposal")).get("validation_status"), 50) or "UNVERIFIED",
                "stage_failure_reason": safe(obj(obj(obj(state.get("context")).get("dynamic_investigation")).get("config_proposal")).get("stage_failure_reason"), 75) or "not_recorded",
                "current_configuration": None,
                "proposed_configuration": None,
                "unified_diff": None,
                "current_excerpt": [{
                    "line": row["line"], "content": safe(row.get("content"), 125)
                } for row in arr(obj(obj(obj(state.get("context")).get("dynamic_investigation")).get("config_proposal")).get("current_excerpt"))[:7]
                   if isinstance(row, dict) and type(row.get("line")) is int],
                "proposed_excerpt": [{
                    "line": row["line"], "content": safe(row.get("content"), 125)
                } for row in arr(obj(obj(obj(state.get("context")).get("dynamic_investigation")).get("config_proposal")).get("proposed_excerpt"))[:7]
                   if isinstance(row, dict) and type(row.get("line")) is int],
                "redacted_diff": {
                    "line": obj(obj(obj(obj(state.get("context")).get("dynamic_investigation")).get("config_proposal")).get("redacted_diff")).get("line"),
                    "before": safe(obj(obj(obj(obj(state.get("context")).get("dynamic_investigation")).get("config_proposal")).get("redacted_diff")).get("before"), 125),
                    "after": safe(obj(obj(obj(obj(state.get("context")).get("dynamic_investigation")).get("config_proposal")).get("redacted_diff")).get("after"), 125),
                } if isinstance(obj(obj(obj(state.get("context")).get("dynamic_investigation")).get("config_proposal")).get("redacted_diff"), dict) else None,
                "original_sha256": safe(obj(obj(obj(state.get("context")).get("dynamic_investigation")).get("config_proposal")).get("original_sha256"), 64),
                "candidate_sha256": safe(obj(obj(obj(state.get("context")).get("dynamic_investigation")).get("config_proposal")).get("candidate_sha256"), 64),
                "proposed_change": safe(obj(obj(obj(state.get("context")).get("dynamic_investigation")).get("config_proposal")).get("proposed_change"), 90),
                "candidate_stored": obj(obj(obj(state.get("context")).get("dynamic_investigation")).get("config_proposal")).get("candidate_stored") is True,
                "validation_profile": safe(obj(obj(obj(state.get("context")).get("dynamic_investigation")).get("config_proposal")).get("validation_profile"), 40),
                "redacted_changes": [{
                    "line": x.get("line"), "before": safe(x.get("before"), 180),
                    "after": safe(x.get("after"), 180),
                } for x in arr(obj(obj(obj(state.get("context")).get("dynamic_investigation")).get("config_proposal")).get("redacted_changes"))[:12]
                  if isinstance(x, dict) and type(x.get("line")) is int],
                "test_scope": safe(obj(obj(obj(state.get("context")).get("dynamic_investigation")).get("config_proposal")).get("test_scope"), 100),
                "format_validation_status": safe(obj(obj(obj(state.get("context")).get("dynamic_investigation")).get("config_proposal")).get("format_validation_status"), 80),
                "vendor_validation_status": safe(obj(obj(obj(state.get("context")).get("dynamic_investigation")).get("config_proposal")).get("vendor_validation_status"), 80),
                "validator_executed_on_proposal": obj(obj(obj(state.get("context")).get("dynamic_investigation")).get("config_proposal")).get("validator_executed_on_proposal") is True,
                "isolated_validation": False,
                "apply_eligible": False,
                "execution_authority": False,
            },
            "execution_authority": False,
            "counts_as_live_evidence": False,
        },
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
            "status": (
                "new_approval_required" if approval.get("status") in {"pending", "approved"} and approval.get("decision_snapshot_status") == "drift_detected" else
                "human_review_required" if approval.get("status") == "pending" else "not_pending"
            ),
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
            "evidence_snapshot_binding": (
                "matched_at_read" if approval.get("decision_snapshot_status") == "matched" else
                "drift_detected" if approval.get("status") in {"pending", "approved"} and approval.get("decision_snapshot_status") == "drift_detected" else
                "not_applicable" if approval.get("decision_snapshot_status") == "not_applicable" else
                "not_verified"
            ),
            "decision_snapshot_version": approval.get("decision_snapshot_version"),
            "data_freshness": data_freshness,
            "approver": safe(approval.get("approver"), 120),
            "warning": "A report never authorizes execution. Approval and one-time workflow resume remain mandatory.",
        },
        "execution_outcome": {
            "status": safe(summary.get("execution_status"), 60),
            "tool": safe(execution.get("tool"), 120),
            "action": safe(execution.get("action"), 120),
            "target": safe(execution.get("target"), 180),
            "error": safe(execution.get("error"), 280),
            "approval_id": safe(execution.get("approval_id"), 180),
            "details": safe(execution.get("reason") or execution.get("result"), 380),
        },
        "verification_result": {
            "status": safe(summary.get("verification_status"), 60),
            "message": safe(verification.get("message"), 350),
            "evidence_refs": refs(verification.get("evidence_refs")),
            "confidence": numeric(verification.get("confidence")),
            "changes": [safe(item, 200) for item in arr(verification.get("changes"))[:12]],
            "metrics": redact(obj(verification.get("comparable_metrics"))),
        },
        "followup_analysis": {
            "status": safe(obj(state.get("followup_analysis")).get("status"), 80) or "not_requested",
            "evidence_ref": safe(obj(state.get("followup_analysis")).get("evidence_ref"), 180),
            "diagnostic": safe(obj(state.get("followup_analysis")).get("diagnostic"), 100),
            "agent_count": obj(state.get("followup_analysis")).get("agent_count", 0),
            "evaluation_status": safe(obj(state.get("followup_analysis")).get("evaluation_status"), 180),
            "decision_status": safe(obj(state.get("followup_analysis")).get("decision_status"), 120),
            "execution_authority": False,
            "knowledge_review_id": safe(obj(knowledge_review).get("id"), 180),
            "knowledge_review_status": safe(obj(knowledge_review).get("status"), 80),
        },
        "knowledge_learning_status": {
            "memory_id": safe(obj(summary.get("memory")).get("memory_entry_id"), 180),
            "review_id": safe(obj(knowledge_review).get("id"), 180),
            "review_status": safe(obj(knowledge_review).get("status"), 80),
            "review_available": (
                str(summary.get("verification_status")).lower() in {"success", "verified", "succeeded"}
                and bool(obj(summary.get("memory")).get("memory_entry_id"))
                and bool(obj(knowledge_review).get("id"))
            ) or (
                obj(state.get("followup_analysis")).get("status") == "reassessed_read_only"
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
    from apps.incident_remediation_opportunities import build_remediation_opportunities
    recorded["remediation_opportunities"] = build_remediation_opportunities(
        incident=incident, evidence=evidence, report=recorded,
    )
    # The approval/review snapshot must bind operational facts, not the wall
    # clock. Elapsed duration is a display-only derived value that changes on
    # every GET; hashing it makes a pending approval impossible to confirm.
    # Keep it in the response but omit it ONLY from the snapshot input.
    # Material changes (evidence, action, approval, freshness category, etc.)
    # still invalidate the review and require a fresh authorization.
    snapshot_payload = redact(recorded)
    snapshot_payload["incident_summary"] = dict(snapshot_payload["incident_summary"])
    snapshot_payload["incident_summary"].pop("elapsed_seconds", None)
    canonical = json.dumps(snapshot_payload, sort_keys=True, ensure_ascii=False, default=str)
    snapshot = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    return {
        "contract_version": CONTRACT_VERSION,
        "snapshot_id": snapshot,
        "generated_at": now.isoformat(),
        **redact(recorded),
        "presentation_context": operator_presentation_context(
            incident, state, evidence, summary,
        ),
        "source_policy": {"durable_only": True, "read_only": True, "authorizes_execution": False},
    }
