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
    llm_plan, vm_binding, vm_read,
)
from apps.orchestrator.dynamic_investigation import DynamicInvestigationPlanner
from apps.orchestrator.workflow_store import WorkflowCheckpointStore
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
        .order_by(desc(Evidence.created_at)).limit(180)
    )).scalars().all()
    evidence = [{"source": r.source, "raw_data": r.raw_data or {},
                 "reference": r.reference, "created_at": str(r.created_at)}
                for r in reversed(rows)]
    return incident, checkpoint, evidence


def _safe_brief(brief: dict) -> dict:
    summary = brief.get("incident_summary") or {}
    return {
        "incident_summary": {
            "service": summary.get("service"),
            "title": redact_text(str(summary.get("summary") or ""))[:450],
            "likely_cause": redact_text(str(summary.get("likely_cause") or ""))[:650],
        },
        "agents": [
            {"agent": item.get("agent"), "confidence": item.get("confidence"),
             "findings": redact(item.get("findings") or [])}
            for item in (brief.get("agents") or [])[:8] if isinstance(item, dict)
        ],
        "recovery_advisory": redact(brief.get("recovery_advisory") or {}),
        "dynamic_investigation": redact(brief.get("dynamic_investigation") or {}),
        "missing_evidence": list(brief.get("missing_evidence") or [])[:8],
        "knowledge": redact({
            "cognia": (brief.get("knowledge") or {}).get("cognia"),
            "memory": (brief.get("knowledge") or {}).get("memory"),
        }),
    }


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
    binding = vm_binding(incident.service, evidence, (checkpoint.get("state") or {}).get("context"))
    return {"incident_id": str(incident_id), "service": incident.service,
            "items": history(events), "approvals": approvals,
            "vm_bound": binding is not None, "status": "ready"}


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
        binding = vm_binding(incident.service, evidence, (checkpoint.get("state") or {}).get("context"))
        if _explicit_wrong_target(payload.message, binding):
            raise HTTPException(status_code=409, detail="chat_target_must_match_incident")
        brief = await load_decision_brief_for_incident(db, incident_id)
        summary = _safe_brief(brief)
        summary["service"] = incident.service
        summary["vm_binding"] = binding or {"status": "not_verified"}
        summary["previous_tool_observations"] = [
            (row.get("metadata") or {}).get("observation")
            for row in (await audit.list(str(incident_id), 60))
            if row.get("event_type") == "incident_copilot_read"
        ][:2]
        await append_turn(audit, incident_id=str(incident_id),
                          actor=identity.subject, role="user", message=payload.message)
        plan = await llm_plan(payload.message, summary, previous)
        requested = fallback_intent(payload.message)
        intent = plan["intent"]
        # Explicit action/read requests must not be ignored by a model's
        # free-form answer; model suggestions are otherwise advisory only.
        if requested != "answer" and intent == "answer":
            intent = requested
        refs = (binding or {}).get("evidence_refs") or []
        observation = None
        kind = "answer"
        proposal = None
        if intent in READ_ACTIONS:
            if intent == "knowledge_search":
                observation = await _read_cognia(
                    payload.message, str(incident.service),
                    (checkpoint.get("state") or {}).get("context") or {},
                    incident_id,
                )
            elif binding is None:
                observation = {"success": False, "status": "target_not_verified"}
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
            followup = await llm_plan(payload.message, summary, previous,
                                      observation=observation)
            kind = "tool_result"
            answer = followup["answer"] or (
                "نتیجه بررسی زنده با MCP ثبت شد." if observation.get("success") else
                "بررسی زنده انجام نشد؛ اتصال، مجوز یا هویت میزبان را بررسی کنید."
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
                "بر اساس شواهد ثبت‌شده پاسخ قطعی ندارم. می‌توانید وضعیت سرویس، "
                "لاگ‌ها یا اعتبار کانفیگ را برای بررسی زنده درخواست کنید."
            )
        answer = redact_text(answer)[:3500]
        event_id = await append_turn(
            audit, incident_id=str(incident_id), actor=identity.subject,
            role="assistant", message=answer, kind=kind, proposal=proposal, refs=refs,
        )
    return {
        "id": event_id, "incident_id": str(incident_id),
        "kind": kind, "message": answer, "proposal": proposal,
        "source_refs": refs, "observation": observation, "model_status": plan["model_status"],
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
