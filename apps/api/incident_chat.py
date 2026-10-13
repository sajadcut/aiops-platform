"""Incident Room copilot API: contextual chat, bounded diagnostics and approval requests."""
from __future__ import annotations

import asyncio
import re
from datetime import datetime, timezone, timedelta
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import desc, select, text

from apps.api.incident_resources import load_decision_brief_for_incident
from apps.api.remediation import RemediationRequest, create_remediation_request
from apps.audit_service.postgres import PostgreSQLAuditStore
from apps.incident_copilot import (
    READ_ACTIONS, WRITE_SUGGESTIONS, append_turn, fallback_intent, history,
    llm_plan, vm_binding, vm_read, asks_for_recorded_errors, recorded_error_facts,
    recorded_error_answer, nginx_inspection_answer, merge_incident_evidence,
    unsupported_security_exclusion_claim,
)
from apps.orchestrator.dynamic_investigation import DynamicInvestigationPlanner
from apps.incident_elastic import (
    elastic_live_read, elastic_answer, stored_elastic_observations,
)
from apps.orchestrator.workflow_store import WorkflowCheckpointStore
from apps.incident_vm_identity import (
    incident_vm_context, vm_binding_diagnostic, resolve_vm_binding,
    vm_status_answer,
)
from apps.runbook_service.runtime_guard import RunbookRuntimeGuard
from apps.security.auth import require_permission
from database import AsyncSessionLocal
from domain.contracts.rate_limit import rate_limiter_strict
from domain.contracts.redaction import redact, redact_text
from domain.models import Evidence, Incident

router = APIRouter()


class IncidentChatMessage(BaseModel):
    message: str = Field(min_length=1, max_length=4000)


class IncidentChatActionRequest(BaseModel):
    proposal_id: UUID


async def _scope(db, incident_id: UUID) -> tuple[Incident, dict, list[dict]]:
    incident = await db.get(Incident, incident_id)
    if incident is None:
        raise HTTPException(status_code=404, detail="incident_not_found")
    checkpoint = await WorkflowCheckpointStore(db).load(str(incident_id)) or {}
    if str(checkpoint.get("status") or "") not in {"completed", "paused", "failed"}:
        raise HTTPException(status_code=409, detail="incident_analysis_not_finished")
    rows = (await db.execute(
        select(Evidence).where(Evidence.incident_id == incident_id)
        .order_by(desc(Evidence.created_at)).limit(500)
    )).scalars().all()
    vm_rows = (await db.execute(
        select(Evidence).where(
            Evidence.incident_id == incident_id, Evidence.source == "vm_mcp",
        ).order_by(desc(Evidence.created_at)).limit(350)
    )).scalars().all()
    seen_ids = set()
    evidence = []
    for row in list(reversed(vm_rows)) + list(reversed(rows)):
        if row.id in seen_ids:
            continue
        seen_ids.add(row.id)
        evidence.append({
            "source": row.source, "raw_data": row.raw_data or {},
            "reference": row.reference, "created_at": str(row.created_at),
            "id": str(row.id),
        })
    return incident, checkpoint, merge_incident_evidence(evidence, checkpoint)


def _safe_brief(brief: dict) -> dict:
    """Keep actual DecisionBrief field names; use bounded persisted facts only."""
    summary = brief.get("incident_summary") or {}
    agents = brief.get("agent_findings") or []
    mcp = brief.get("mcp_evidence") or []
    config = brief.get("configuration_diagnostic") or {}
    result = {
        "incident_summary": {
            "service": summary.get("service"),
            "title": redact_text(str(summary.get("summary") or ""))[:450],
            "likely_cause": redact_text(str(summary.get("likely_cause") or ""))[:650],
            "cause_status": summary.get("cause_status"),
        },
        "agent_findings": [{
            "agent": str(item.get("agent") or "")[:80],
            "status": item.get("status"),
            "confidence": item.get("confidence"),
            "finding": redact_text(str(item.get("finding") or ""))[:340],
            "findings": [
                redact_text(str(finding))[:220]
                for finding in (item.get("findings") or [])[:4]
            ],
            "evidence_refs": list(item.get("evidence_refs") or [])[:5],
        } for item in agents[:12] if isinstance(item, dict)],
        "mcp_evidence": [{
            "tool": str(item.get("tool") or "")[:90],
            "status": str(item.get("status") or "")[:50],
            "semantic_result": item.get("semantic_result"),
            "finding": redact_text(str(item.get("finding") or ""))[:380],
            "evidence_ref": str(item.get("evidence_ref") or "")[:160],
            "collected_at": item.get("collected_at"),
        } for item in mcp[:65] if isinstance(item, dict)],
        "configuration_diagnostic": redact({
            key: config.get(key) for key in (
                "status", "config_file", "error_line", "error_column",
                "error_code", "syntax_error", "evidence_refs", "validated_scope"
            )
        }) if isinstance(config, dict) else {},
        "recovery_advisory": redact(brief.get("recovery_advisory") or {}),
        "rca_assessment": redact(brief.get("rca_assessment") or {}),
        "missing_evidence": list(brief.get("missing_evidence") or [])[:8],
        "knowledge": {
            "cognia_status": (brief.get("cognia_knowledge") or {}).get("status"),
            "cognia_count": (brief.get("cognia_knowledge") or {}).get("retrieved_count"),
            "memory_status": (brief.get("operational_memory") or {}).get("status"),
        },
    }
    result["recorded_error_facts"] = recorded_error_facts(result)
    return result


def _explicit_wrong_target(message: str, binding: dict | None) -> bool:
    if not binding:
        return False
    for token in re.findall(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])", message):
        if token != binding["target"]:
            return True
    known = binding["service"].lower()
    for pattern in (r"(?:سرویس|service)\s+([A-Za-z][A-Za-z0-9_.-]{1,60})",
                    r"([A-Za-z][A-Za-z0-9_.-]{1,60})\s+(?:سرویس|service)"):
        for hit in re.findall(pattern, message, re.I):
            if hit.lower().removesuffix(".service") not in {known, "this", "the"}:
                return True
    return False


async def _read_cognia(question: str, service: str, context: dict,
                       incident_id: UUID) -> dict:
    from apps.rag_service import KnowledgeRAGService
    scope, allowed = DynamicInvestigationPlanner._scope(context)
    if not allowed:
        return {"success": False, "status": "knowledge_scope_unavailable"}
    query = redact_text(f"{service} incident troubleshooting: {question}")[:420]
    try:
        docs = await asyncio.wait_for(
            KnowledgeRAGService().search(
                query, limit=3, scope_context=scope,
                incident_id=str(incident_id), phase="incident_copilot_followup",
            ), timeout=8.0,
        )
    except Exception:
        return {"success": False, "status": "knowledge_unavailable"}
    return {"success": True, "status": "retrieved", "documents": [
        {"source_ref": str(item.get("source_id") or "")[:120],
         "excerpt": redact_text(str(item.get("excerpt") or item.get("content") or ""))[:500]}
        for item in docs[:3] if isinstance(item, dict) and item.get("source_id")
    ]}


@router.get("/incidents/{incident_id}/chat")
async def incident_chat_history(
    incident_id: UUID,
    identity=Depends(require_permission("read:incident")),
):
    async with AsyncSessionLocal() as db:
        incident, checkpoint, evidence = await _scope(db, incident_id)
        events = await PostgreSQLAuditStore(db).list(str(incident_id), 200)
        requested = {
            str((event.get("metadata") or {}).get("proposal_id")):
                str((event.get("metadata") or {}).get("approval_id"))
            for event in events
            if event.get("event_type") == "incident_copilot_approval_requested"
            and isinstance(event.get("metadata"), dict)
        }
        approvals = {}
        if requested:
            rows = (await db.execute(
                text("SELECT approval_id,status,action FROM approvals "
                     "WHERE incident_id=:incident_id ORDER BY created_at DESC LIMIT 100"),
                {"incident_id": str(incident_id)}
            )).mappings().all()
            status_by_id = {str(row["approval_id"]): row for row in rows}
            approvals = {
                proposal_id: {
                    "approval_id": approval_id,
                    "status": str(status_by_id[approval_id]["status"]),
                    "action": str(status_by_id[approval_id]["action"]),
                }
                for proposal_id, approval_id in requested.items()
                if approval_id in status_by_id
            }
    ctx = incident_vm_context(incident.context, checkpoint)
    binding = vm_binding(incident.service, evidence, ctx) if not ctx.get("_vm_identity_context_conflicts") else None
    diagnosis = vm_binding_diagnostic(incident.service, evidence, ctx)
    return {"incident_id": str(incident_id), "service": incident.service,
            "items": history(events), "approvals": approvals,
            "vm_bound": binding is not None,
            "vm_binding_status": "verified" if binding else diagnosis["reason"],
            "vm_live_recheck_possible": bool(diagnosis.get("candidate")),
            "status": "ready"}


@router.post(
    "/incidents/{incident_id}/chat",
    dependencies=[Depends(rate_limiter_strict)],
)
async def incident_chat_message(
    incident_id: UUID, payload: IncidentChatMessage,
    identity=Depends(require_permission("read:incident")),
):
    async with AsyncSessionLocal() as db:
        incident, checkpoint, evidence = await _scope(db, incident_id)
        audit = PostgreSQLAuditStore(db)
        previous = history(await audit.list(str(incident_id), 200))
        vm_context = incident_vm_context(incident.context, checkpoint)
        binding = vm_binding(incident.service, evidence, vm_context) if not vm_context.get("_vm_identity_context_conflicts") else None
        binding_diagnosis = vm_binding_diagnostic(incident.service, evidence, vm_context)
        if _explicit_wrong_target(payload.message, binding):
            raise HTTPException(status_code=409, detail="chat_target_must_match_incident")
        brief = await load_decision_brief_for_incident(db, incident_id)
        summary = _safe_brief(brief)
        summary["service"] = incident.service
        summary["vm_binding"] = binding or {"status": "not_verified"}
        summary["elastic_recorded"] = stored_elastic_observations(
            evidence, service=str(incident.service or ""),
        )
        summary["previous_tool_observations"] = [
            (row.get("metadata") or {}).get("observation")
            for row in (await audit.list(str(incident_id), 60))
            if row.get("event_type") == "incident_copilot_read"
        ][:2]
        await append_turn(audit, incident_id=str(incident_id),
                          actor=identity.subject, role="user", message=payload.message)
        plan = await llm_plan(payload.message, summary, previous)
        requested = fallback_intent(payload.message)
        historical_errors = asks_for_recorded_errors(payload.message)
        intent = "answer" if historical_errors else plan["intent"]
        # Explicit action/read requests must not be ignored by a model's
        # free-form answer; model suggestions are otherwise advisory only.
        if requested in WRITE_SUGGESTIONS:
            # An explicit operator Start/Restart/Reload always takes
            # precedence over a different action proposed by an LLM.
            intent = requested
        elif requested in {"elastic_logs", "elastic_recorded"}:
            # Never let a model convert an ELK question to a VM journal read
            # or invent an Elastic result from unrelated diagnostics.
            intent = requested
        elif requested == "nginx_config_inspect" and not historical_errors:
            # An explicit request to inspect files must not become a vague
            # no-access model answer or an unrelated diagnostic.
            intent = requested
        elif requested != "answer" and intent == "answer":
            intent = requested
        vm_actions = READ_ACTIONS - {"knowledge_search", "elastic_logs", "elastic_recorded"}
        if intent in vm_actions or intent in WRITE_SUGGESTIONS:
            binding, binding_diagnosis = await resolve_vm_binding(
                incident.service, evidence, vm_context,
                force_live=(intent in WRITE_SUGGESTIONS),
            )
            if _explicit_wrong_target(payload.message, binding):
                raise HTTPException(status_code=409, detail="chat_target_must_match_incident")
            summary["vm_binding"] = binding or {"status": binding_diagnosis["status"]}
        refs = (binding or {}).get("evidence_refs") or []
        if historical_errors:
            refs = list(dict.fromkeys(
                ref for fact in summary["recorded_error_facts"]
                for ref in fact.get("source_refs", [])
            ))[:10]
        observation = None
        final_model_status = plan["model_status"]
        answer_basis = "stored_analysis" if historical_errors else "model_narration"
        kind = "answer"
        proposal = None
        if intent in READ_ACTIONS:
            if intent == "elastic_recorded":
                observation = summary["elastic_recorded"]
            elif intent == "elastic_logs":
                observation = await elastic_live_read(
                    str(incident.service or ""), incident_started_at=incident.started_at,
                )
            elif intent == "knowledge_search":
                observation = await _read_cognia(
                    payload.message, str(incident.service),
                    (checkpoint.get("state") or {}).get("context") or {},
                    incident_id,
                )
            elif binding is None:
                observation = {"success": False, "status": "target_not_verified",
                               "binding_reason": binding_diagnosis.get("status", "unverified")}
            elif intent == "service_status" and binding_diagnosis.get("live_observation"):
                from apps.incident_copilot import public_result
                observation = public_result("service_status", binding_diagnosis["live_observation"])
            else:
                try:
                    observation = await vm_read(intent, binding)
                except Exception:
                    observation = {"success": False, "status": "mcp_unavailable"}
            await audit.append({
                "event_id": str(__import__("uuid").uuid4()),
                "event_type": "incident_copilot_read", "actor": identity.subject,
                "incident_id": str(incident_id), "action": intent, "status": "recorded",
                "metadata": redact({"action": intent, "observation": observation,
                                    "source_refs": refs}),
                "created_at": datetime.now(timezone.utc).isoformat(),
            })
            kind = "tool_result"
            answer_basis = (
                "stored_elasticsearch_evidence" if intent == "elastic_recorded" else
                "live_elasticsearch_mcp" if intent == "elastic_logs" and observation.get("success") else
                "elastic_mcp_unavailable" if intent == "elastic_logs" else
                "live_mcp" if observation.get("success") else
                "stored_analysis_live_unavailable"
            )
            if intent in {"elastic_recorded", "elastic_logs"}:
                # The structured observation, not model fluency, establishes
                # whether a query ran and what results were actually returned.
                answer = elastic_answer(
                    observation, persian=bool(re.search(r"[\u0600-\u06ff]", payload.message)),
                )
                refs = list(dict.fromkeys(refs + (observation.get("evidence_refs") or [])))[:12]
                if intent == "elastic_logs" and observation.get("success"):
                    followup = await llm_plan(payload.message, summary, previous, observation=observation)
                    final_model_status = followup["model_status"]
                    # No ungated LLM claims about absence of errors or health
                    # are appended to a bounded log result.
            elif observation.get("success"):
                followup = await llm_plan(payload.message, summary, previous,
                                          observation=observation)
                final_model_status = followup["model_status"]
                answer = followup["answer"] or (
                    "بررسی زنده انجام شد، اما LLM نتوانست نتیجه را خلاصه کند. "
                    "نتیجهٔ ثبت‌شدهٔ ابزار را در شواهد مشاهده کنید."
                )
                if intent == "service_status":
                    answer = vm_status_answer(
                        observation,
                        persian=bool(re.search(r"[\u0600-\u06ff]", payload.message)),
                    )
                if intent == "nginx_config_inspect":
                    factual = nginx_inspection_answer(
                        observation,
                        persian=bool(re.search(r"[\u0600-\u06ff]", payload.message)),
                    )
                    if (followup["model_status"] == "structured" and
                        followup["answer"] and not re.search(
                            r"دسترسی.{0,65}ندار|امکان.{0,65}نیست|"
                            r"cannot access|no filesystem access|unable to read", answer, re.I
                        )):
                        answer = factual + "\n\nتفسیر LLM: " + answer
                    else:
                        answer = factual
            else:
                reason = str(observation.get("status") or "mcp_unavailable")[:70]
                if intent == "nginx_config_inspect":
                    answer = nginx_inspection_answer(
                        observation,
                        persian=bool(re.search(r"[\u0600-\u06ff]", payload.message)),
                    ) + "\n\n" + recorded_error_answer(
                        summary,
                        persian=bool(re.search(r"[\u0600-\u06ff]", payload.message)),
                        live_failure=reason,
                    )
                else:
                    answer = recorded_error_answer(
                    summary, persian=bool(re.search(r"[\u0600-\u06ff]", payload.message)),
                    live_failure=reason,
                )
        elif intent in WRITE_SUGGESTIONS:
            kind = "action_proposal"
            action = WRITE_SUGGESTIONS[intent]
            if binding is not None:
                proposal = {
                    "action": action, "service": binding["service"],
                    "target": binding["target"], "risk_level": "high",
                    "status": "requires_preflight_and_approval",
                    "execution_authority": False,
                }
                answer = (
                    plan["answer"] or f"پیشنهاد {action} برای سرویس این رخداد آماده بررسی است."
                ) + "\nهیچ عملیات اجرایی انجام نشده است. درخواست تأیید تنها پس از بررسی زنده شرایط ایمنی ساخته می‌شود."
            else:
                answer = "مقصد و سرویس این رخداد با شواهد MCP تأیید نشده است؛ امکان درخواست عملیات وجود ندارد."
        else:
            answer = plan["answer"] or (
                "بر اساس گزارش فعلی برای پاسخ قطعی دادهٔ کافی وجود ندارد؛ "
                "می‌توانید بررسی زندهٔ مشخصی درخواست کنید."
            )
            if historical_errors:
                grounded = recorded_error_answer(
                    summary, persian=bool(re.search(r"[\u0600-\u06ff]", payload.message)),
                )
                # Always expose concrete persisted diagnostics, regardless of
                # whether the model replies vaguely or selects a live tool.
                answer = (answer + "\n\n" + grounded) if (
                    plan["model_status"] == "structured" and summary["recorded_error_facts"]
                    and plan["answer"]
                ) else grounded
        if (
            kind == "answer" and
            unsupported_security_exclusion_claim(answer)
        ):
            # Without verified, complete authentication event coverage, an
            # LLM cannot conclude there were no 401/403 responses. Surface
            # the stored diagnostics instead of asserting a false negative.
            answer = (
                recorded_error_answer(
                    summary,
                    persian=bool(re.search(r"[\u0600-\u06ff]", payload.message)),
                )
                + "\n\n"
                + (
                    "نبود خطای احراز هویت از لاگ‌های محدود اثبات نمی‌شود؛ "
                    "برای بررسی، استعلام زندهٔ Elasticsearch MCP را درخواست کنید."
                    if re.search(r"[\u0600-\u06ff]", payload.message)
                    else "A bounded log sample cannot rule out authentication failures. "
                         "Request a live Elasticsearch MCP query for more evidence."
                )
            )
            answer_basis = "stored_analysis_guarded"
        answer = redact_text(answer)[:3500]
        event_id = await append_turn(
            audit, incident_id=str(incident_id), actor=identity.subject,
            role="assistant", message=answer, kind=kind, proposal=proposal,
            refs=refs, model_status=final_model_status, answer_basis=answer_basis,
        )
    return {
        "id": event_id, "incident_id": str(incident_id),
        "kind": kind, "message": answer, "proposal": proposal,
        "source_refs": refs, "observation": observation,
        "model_status": final_model_status, "answer_basis": answer_basis,
    }


@router.post(
    "/incidents/{incident_id}/chat/request-approval",
    dependencies=[Depends(rate_limiter_strict)],
)
async def incident_chat_request_approval(
    incident_id: UUID, payload: IncidentChatActionRequest,
    identity=Depends(require_permission("approve:high_risk")),
):
    async with AsyncSessionLocal() as db:
        incident, checkpoint, evidence = await _scope(db, incident_id)
        context = (checkpoint.get("state") or {}).get("context") or {}
        binding = vm_binding(incident.service, evidence, context)
        if binding is None:
            raise HTTPException(status_code=409, detail="incident_vm_identity_unverified")
        # Lock the proposal scope transactionally, rejecting duplicate requests
        # even if two operator browser tabs send simultaneously.
        await db.execute(text("SELECT pg_advisory_xact_lock(hashtext(:key))"),
                         {"key": "incident_chat:" + str(payload.proposal_id)})
        audit = PostgreSQLAuditStore(db)
        events = await audit.list(str(incident_id), 200)
        if any(e.get("event_type") == "incident_copilot_approval_requested"
               and (e.get("metadata") or {}).get("proposal_id") == str(payload.proposal_id)
               for e in events):
            raise HTTPException(status_code=409, detail="chat_proposal_already_requested")
        item = next((
            e for e in events
            if e.get("event_type") == "incident_copilot_turn"
            and str(e.get("event_id")) == str(payload.proposal_id)
        ), None)
        meta = (item or {}).get("metadata") or {}
        proposal = meta.get("proposal") or {}
        if (meta.get("role") != "assistant" or
                proposal.get("status") != "requires_preflight_and_approval" or
                proposal.get("execution_authority") is not False or
                proposal.get("service") != binding["service"] or
                proposal.get("target") != binding["target"] or
                proposal.get("action") not in WRITE_SUGGESTIONS.values()):
            raise HTTPException(status_code=409, detail="unverified_or_stale_chat_proposal")
        created = item.get("created_at")
        if (not isinstance(created, datetime)
            or created.replace(tzinfo=created.tzinfo or timezone.utc) <
                datetime.now(timezone.utc) - timedelta(minutes=15)):
            raise HTTPException(status_code=409, detail="chat_proposal_expired")
        action = proposal["action"]
        params = {"service": binding["service"]}
        snapshot = await RunbookRuntimeGuard.collect_snapshot(
            runbook_id=RunbookRuntimeGuard.VM_SERVICE_RUNBOOK,
            target=binding["target"], parameters=params,
            incident_id=str(incident_id), phase="chat_preapproval",
        )
        preflight = RunbookRuntimeGuard.preflight(
            runbook_id=RunbookRuntimeGuard.VM_SERVICE_RUNBOOK,
            tool_name="ssh_vm", action=action, target=binding["target"],
            parameters=params, incident_id=str(incident_id),
            evidence=list(snapshot.get("evidence") or []),
        )
        if not preflight.get("safe_to_execute"):
            raise HTTPException(status_code=409, detail={
                "code": "chat_live_preflight_blocked",
                "reason": preflight.get("reason") or snapshot.get("error"),
            })
        # Existing protected remediation API creates a separate, bound pending
        # Approval. This route never approves, executes or reloads any service.
        approved_request = await create_remediation_request(
            incident_id, RemediationRequest(
                target=binding["target"], service=binding["service"],
                action=action, reason="Incident chat proposal: "+str(payload.proposal_id),
            ), identity=identity,
        )
        await audit.append({
            "event_id": str(__import__("uuid").uuid4()),
            "event_type": "incident_copilot_approval_requested",
            "actor": identity.subject, "incident_id": str(incident_id),
            "action": action, "status": "waiting",
            "metadata": {
                "proposal_id": str(payload.proposal_id),
                "approval_id": str(approved_request["approval_id"]),
                "action": action, "target": binding["target"],
                "service": binding["service"],
                "preflight_refs": preflight.get("evidence_refs", []),
                "execution_authority": False,
            },
            "created_at": datetime.now(timezone.utc).isoformat(),
        })
    return {
        "status": "pending_approval", "approval_id": str(approved_request["approval_id"]),
        "action": action, "target": binding["target"], "service": binding["service"],
        "executed": False,
    }
