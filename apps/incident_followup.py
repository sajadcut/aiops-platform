"""Evidence-bound continuation of a terminal, no-action Incident via chat.

A live *read-only* operator-requested diagnostic is stored in the canonical
Evidence table, then specialist findings, RCA and Evaluation are recalculated.
This pathway NEVER calls Decision/Approval/Execution/Verification and cannot
create an executable request. Knowledge is a local Cognia-review *draft* only.
"""
from __future__ import annotations

import asyncio
import json
from datetime import datetime, timezone
from typing import Any, Mapping
from uuid import UUID, uuid4

from sqlalchemy import select, text

from apps.incident_service.repository import IncidentRepository
from apps.orchestrator.workflow_store import WorkflowCheckpointStore
from domain.contracts.redaction import redact, redact_text
from domain.models import Evidence, KnowledgeReview


_LIVE_VM_CHECKS = frozenset({
    "service_status", "service_logs", "config_validate", "nginx_config_review",
    "nginx_config_inspect", "service_runtime_discovery", "service_config_discovery", "service_config_review", "dotnet_config_syntax",
})
_LIVE_CHECKS = _LIVE_VM_CHECKS | {"elastic_logs"}


def followup_evidence(
    *, action: str, observation: Mapping[str, Any] | None,
    service: str, binding: Mapping[str, Any] | None, reference: str,
    now: datetime | None = None,
) -> dict | None:
    """Allowlist real MCP responses, never a model answer or cached search.

    Provider payloads are bounded/redacted upstream. A successful transport
    does not itself imply application health, diagnostic matches or valid JSON.
    """
    o = observation if isinstance(observation, Mapping) else {}
    if action not in _LIVE_CHECKS or o.get("success") is not True:
        return None
    at = (now or datetime.now(timezone.utc)).isoformat()
    if action == "elastic_logs":
        if (o.get("is_live") is not True
                or str(o.get("searched_service") or "").lower() != service.lower()):
            return None
        raw = {
            "diagnostic": "elastic_logs", "tool": "elastic_logs",
            "mcp_server": "elasticsearch", "success": True,
            "service": service, "phase": "incident_copilot_followup",
            "collected_at": at,
            "status": "queried", "result_count": int(o.get("returned_count") or 0),
            "results_are_sampled": True, "absence_of_errors_proven": False,
            "levels": redact(o.get("levels") or {}),
            "results": redact((o.get("results") or [])[:8]),
        }
        source = "elasticsearch"
    else:
        if (not isinstance(binding, Mapping)
                or not binding.get("service") or not binding.get("target")
                or str(binding["service"]).lower().removesuffix(".service") != service.lower().removesuffix(".service")):
            return None
        # Reject a provider result for a different unit or VM instead of
        # overwriting its source identity with the Incident binding.
        returned_service = str(o.get("service") or "").lower().removesuffix(".service")
        returned_target = str(o.get("target") or "").strip()
        if (returned_service and returned_service != str(binding["service"]).lower().removesuffix(".service")
                or returned_target and returned_target != str(binding["target"])):
            return None
        # Binding comes from the VM identity verifier, not an LLM or a
        # user-selected cross-host destination.
        raw = redact(dict(o))
        raw.update({
            "diagnostic": action, "success": True,
            "service": binding["service"], "target": binding["target"],
            "phase": "incident_copilot_followup", "collected_at": at,
        })
        source = "vm_mcp"
    return {
        "type": "telemetry" if action != "elastic_logs" else "log",
        "source": source, "reference": reference,
        "raw_data": raw, "confidence": 1.0,
    }


def may_reassess(checkpoint: Mapping[str, Any], approval_status: str | None = None) -> bool:
    """Do not rewrite an active/approved/executed workflow checkpoint."""
    state = checkpoint.get("state") or {}
    if str(checkpoint.get("status") or "") not in {"completed", "failed"}:
        return False
    # A blocked planner may have constructed an unapproved request; that
    # is precisely the kind of no-action case where a read-only reassessment
    # is useful. The request is discarded from the reassessment snapshot.
    if state.get("approval") or state.get("execution_result"):
        return False
    if str(approval_status or "").lower() in {
        "pending", "approved", "consumed", "executing",
    }:
        return False
    return True


def knowledge_candidate(
    *, incident_id: UUID, service: str, evidence_ref: str,
    diagnostic: str, state: Mapping[str, Any],
) -> tuple[str, str]:
    """Sanitized *unverified* learning note; never a claimed recovery."""
    followup = state.get("followup_analysis") or {}
    findings = state.get("analysis_results") or []
    findings_text = [
        redact_text(str(f.get("statement") or ""))[:270]
        for f in findings if isinstance(f, dict) and f.get("statement")
    ][:6]
    # Cite small, non-secret operational facts, not raw logs or configuration
    # values. A reference alone is not a useful reusable troubleshooting note.
    selected_facts = []
    for item in reversed(((state.get("context") or {}).get("evidence") or [])):
        if not isinstance(item, dict) or str(item.get("id") or "") != evidence_ref:
            continue
        raw = item.get("raw_data") or {}
        if isinstance(raw, dict):
            for key in ("active_state", "sub_state", "result", "main_pid",
                        "status", "valid", "syntax_valid", "error_line",
                        "result_count"):
                value = raw.get(key)
                if isinstance(value, (str, int, float, bool)) and len(str(value)) <= 70:
                    selected_facts.append(key + "=" + redact_text(str(value)))
        break
    title = redact_text(f"بررسی تکمیلی رخداد {service} (نیازمند بازبینی)")[:500]
    content = "\n".join([
        "نوع: یادداشت تکمیلی رخداد؛ دانش تأییدشده یا نتیجه بازیابی نیست.",
        f"سرویس: {redact_text(service)[:120]}",
        f"شناسه رخداد: {incident_id}",
        f"شاهد جدید: {evidence_ref}",
        f"نوع بررسی انجام‌شده: {diagnostic}",
        "مشاهدات محدود از ابزار: " + (", ".join(selected_facts) or "جزئیات در شناسهٔ شاهد"),
        f"وضعیت تحلیل: {followup.get('status', 'unknown')}",
        "یافته‌های ایجنت‌ها (تحلیل/فرضیه، نه اثبات علت):",
        *(("- " + item) for item in findings_text),
        "علت ریشه‌ای، اثر عملیات و سلامت نهایی راستی‌آزمایی و مستقلاً تأیید نشده‌اند.",
        "انتشار فقط پس از بازبینی انسانی در مسیر تأیید Cognia مجاز است.",
        "استفاده مجدد نیازمند شواهد زنده، تعیین هدف و Approval عملیاتی مستقل است.",
    ])
    return title, content


async def draft_cognia_review(
    db, *, incident_id: UUID, service: str, evidence_ref: str,
    diagnostic: str, state: Mapping[str, Any],
) -> dict:
    """Create an idempotent local review/outbox entry; do NOT publish to Cognia."""
    from apps.knowledge_review import content_digest, validated_document
    from domain.contracts.config import settings

    ids = list(settings.COGNIA_KNOWLEDGE_BASE_IDS or [])
    app_id = settings.COGNIA_CLIENT_APPLICATION_ID
    if len(ids) != 1 or not app_id:
        return {"status": "configuration_required", "published_to_cognia": False,
                "reason": "single_kb_and_client_application_required"}
    title, content = knowledge_candidate(
        incident_id=incident_id, service=service, evidence_ref=evidence_ref,
        diagnostic=diagnostic, state=state,
    )
    try:
        title, content = validated_document(title, content)
    except Exception:
        return {"status": "redaction_review_required", "published_to_cognia": False}
    # Idempotent per NEW diagnostic reference under the same Incident.
    # Never edit a previously reviewed/approved/published historical revision.
    existing = (await db.execute(
        select(KnowledgeReview).where(
            KnowledgeReview.incident_id == incident_id,
            KnowledgeReview.source_type == "incident_followup",
            KnowledgeReview.review_reason == evidence_ref,
        ).limit(1)
    )).scalars().first()
    if existing:
        return {"status": existing.status, "review_id": str(existing.id),
                "published_to_cognia": existing.status == "published"}
    row = KnowledgeReview(
        id=uuid4(), source_type="incident_followup", incident_id=incident_id,
        kb_id=int(ids[0]),
        scope={"type": "clientApplication", "clientApplicationId": int(app_id)},
        title=title, content=content,
        content_hash=content_digest(title, content),
        status="pending_review", created_by="system:incident_copilot",
        review_reason=evidence_ref,
    )
    db.add(row)
    await db.commit()
    return {"status": "pending_review", "review_id": str(row.id),
            "published_to_cognia": False}


async def persist_and_reassess(
    db, *, incident_id: UUID, incident_service: str,
    checkpoint: Mapping[str, Any], action: str, observation: Mapping[str, Any] | None,
    binding: Mapping[str, Any] | None, actor: str,
    incident_evidence: list[dict] | None = None,
) -> dict:
    """Durably append observation; redo specialists and evaluator if no-action.

    Read-only model work runs after the observation has committed. A failure
    never deletes evidence or silently claims that recalculation happened.
    """
    from apps.audit_service.postgres import PostgreSQLAuditStore

    reference = "chat-mcp:" + str(uuid4())
    item = followup_evidence(
        action=action, observation=observation, service=incident_service,
        binding=binding, reference=reference,
    )
    if item is None:
        return {"status": "not_live_evidence", "reassessed": False}
    repository = IncidentRepository(db)
    await repository.add_evidence(str(incident_id), [item])
    await repository.commit()
    evidence_row = (await db.execute(
        select(Evidence).where(
            Evidence.incident_id == incident_id,
            Evidence.reference == reference,
        ).limit(1)
    )).scalar_one()
    evidence_ref = str(evidence_row.id)
    audit = PostgreSQLAuditStore(db)
    async def emit_status(status: dict) -> dict:
        await audit.append({
            "event_id": str(uuid4()),
            "event_type": "incident_copilot_followup_integrated",
            "actor": actor, "incident_id": str(incident_id),
            "action": action, "status": status["status"],
            "metadata": {
                "evidence_ref": evidence_ref, "reassessed": status["reassessed"],
                "knowledge": status.get("knowledge", {"status": "not_created"}),
                "execution_authority": False,
            },
            "created_at": datetime.now(timezone.utc).isoformat(),
        })
        return status

    status = {
        "status": "evidence_recorded", "evidence_ref": evidence_ref,
        "reassessed": False, "published_to_cognia": False,
    }
    approval = (await db.execute(
        text("SELECT status FROM approvals WHERE incident_id=:id "
             "ORDER BY created_at DESC LIMIT 1"),
        {"id": str(incident_id)},
    )).scalar_one_or_none()
    # Another chat may have advanced this Incident while MCP was reading.
    # Read the latest durable checkpoint, not only the snapshot at request start.
    current = await WorkflowCheckpointStore(db).load(str(incident_id)) or checkpoint
    if not may_reassess(current, str(approval or "")):
        status["status"] = "evidence_recorded_reanalysis_requires_workflow_review"
        return await emit_status(status)

    # Copy checkpoint; never call Decision / Approval / Execution nodes.
    state = json.loads(json.dumps(current.get("state") or {}, default=str))
    from apps.orchestrator.signal_aware import SignalAwareE2EOrchestrator
    from domain.contracts.config import settings
    from domain.contracts.logging import logger
    context = state.setdefault("context", {})
    context_evidence = context.get("evidence") or []
    if not isinstance(context_evidence, list):
        context_evidence = []
    new_observation = {
        "id": evidence_ref, "reference": reference, "source": item["source"],
        "type": item["type"], "raw_data": item["raw_data"],
        "created_at": evidence_row.created_at.isoformat() if evidence_row.created_at else None,
    }
    # Bounded input for specialist re-analysis: original recent observations
    # plus the latest operator-requested source evidence.
    # Re-include earlier successful Copilot probes for iterative reasoning.
    # They came from the same Incident's durable Evidence table through _scope.
    prior_followups = [
        e for e in (incident_evidence or [])
        if isinstance(e, dict)
        and isinstance(e.get("raw_data"), dict)
        and e["raw_data"].get("phase") == "incident_copilot_followup"
    ][-32:]
    merged = {}
    for evidence in [*context_evidence, *prior_followups, new_observation]:
        if not isinstance(evidence, dict):
            continue
        eid = str(evidence.get("id") or evidence.get("reference") or "")
        if eid:
            merged[eid] = evidence
    # Keep the definitive failed validator alongside the new candidate.
    # Otherwise a long 40+ evidence Incident can lose the exact fatal line
    # when bounded to the most recent entries.
    validator = next((
        e for e in reversed(list(merged.values()))
        if e.get("source") == "vm_mcp"
        and isinstance(e.get("raw_data"), dict)
        and e["raw_data"].get("diagnostic") == "config_validate"
        and e["raw_data"].get("success") is True
        and e["raw_data"].get("supported") is True
        and e["raw_data"].get("valid") is False
        and str(e["raw_data"].get("service") or "").lower().removesuffix(".service")
            == incident_service.lower().removesuffix(".service")
    ), None)
    total_limit = max(2, settings.AGENT_MAX_EVIDENCE_ITEMS)
    latest = list(merged.values())
    state["context"]["evidence"] = (
        latest[-total_limit:] if not validator else
        [*[e for e in latest if e is not validator and e is not new_observation][-max(0, total_limit - 2):],
         validator, new_observation]
    )
    state["incident_id"] = str(incident_id)
    state["service_name"] = incident_service
    previous_proposal_present = bool(state.pop("execution_request", None))
    state.pop("approval", None)
    try:
        orchestrator = SignalAwareE2EOrchestrator(db=db)
        selected = [
            name for name in ((state.get("routing") or {}).get("selected") or [])
            if name in orchestrator.registry.enabled_names()
        ][:settings.AGENT_MAX_PARALLELISM]
        if not selected:
            selected = [name for name in ("vm", "application", "network")
                        if name in orchestrator.registry.enabled_names()][:settings.AGENT_MAX_PARALLELISM]
        if not selected:
            status["status"] = "evidence_recorded_no_specialists_available"
            return await emit_status(status)
        findings = await orchestrator._run_specialists(selected, state)
        if not any(f.get("evidence_ids") or f.get("evidence_count") for f in findings):
            status["status"] = "evidence_recorded_specialists_inconclusive"
            return await emit_status(status)
        state["analysis_results"] = findings
        state["findings"] = [state.get("triage_result") or {}] + findings
        state["coordination"] = orchestrator.coordinator.synthesize(findings)
        # Every read-only service configuration probe refreshes the durable
        # diagnostic proposal, not only Nginx. Nothing here may execute.
        if action in {
            "nginx_config_review", "config_validate", "dotnet_config_syntax",
            "service_runtime_discovery", "service_config_discovery",
            "service_config_review",
        }:
            from apps.orchestrator.dynamic_investigation import DynamicInvestigationPlanner
            try:
                state["context"]["dynamic_investigation"] = (
                    await DynamicInvestigationPlanner.propose(
                        state, adapter=None,
                    )
                )
            except Exception:
                # Evidence and agent analysis remain durable even if the
                # optional LLM planner is unavailable.
                pass
        await orchestrator._rca_node(state)
        await orchestrator._evaluator_node(state)
        state["followup_analysis"] = {
            "status": "reassessed_read_only",
            "evidence_ref": evidence_ref,
            "diagnostic": action,
            "agent_count": len(findings),
            "evaluation_status": (state.get("evaluation") or {}).get("reason") or
                                 "reevaluated_not_approved",
            "decision_status": "human_review_required_no_automatic_action",
            "execution_authority": False,
            "previous_unapproved_proposal_present": previous_proposal_present,
            "updated_at": datetime.now(timezone.utc).isoformat(),
        }
        for finding in findings:
            if not isinstance(finding, dict):
                continue
            finding["finding_type"] = "copilot_followup_" + str(finding.get("agent_name") or "agent")[:70]
        # Serialize concurrent operator re-evaluations until the checkpoint
        # commit. Do not overwrite a newer decision or another follow-up.
        await db.execute(
            text("SELECT pg_advisory_xact_lock(hashtext(:key))"),
            {"key": "incident_followup:" + str(incident_id)},
        )
        newest = await WorkflowCheckpointStore(db).load(str(incident_id)) or current
        if (current.get("version") is not None
                and newest.get("version") != current.get("version")):
            status["status"] = "evidence_recorded_concurrent_reanalysis"
            await db.rollback()
            return await emit_status(status)
        if not may_reassess(newest, str(approval or "")):
            status["status"] = "evidence_recorded_workflow_changed"
            await db.rollback()
            return await emit_status(status)
        await repository.add_findings(str(incident_id), findings)
        await WorkflowCheckpointStore(db).save(
            str(incident_id), state, status=str(current.get("status")),
        )
        status["status"] = "reassessed_read_only"
        status["reassessed"] = True
        status["agent_count"] = len(findings)
        try:
            kb = await draft_cognia_review(
                db, incident_id=incident_id, service=incident_service,
                evidence_ref=evidence_ref, diagnostic=action, state=state,
            )
            status["knowledge"] = kb
        except Exception as exc:
            logger.error("incident_followup_knowledge_draft_failed",
                         incident_id=str(incident_id), error_type=type(exc).__name__)
            status["knowledge"] = {"status": "draft_failed", "published_to_cognia": False}
    except Exception as exc:
        logger.error("incident_followup_reassessment_failed",
                     incident_id=str(incident_id), error_type=type(exc).__name__)
        status["status"] = "evidence_recorded_reassessment_failed"
        await db.rollback()
    return await emit_status(status)
