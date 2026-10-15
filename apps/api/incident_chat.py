"""Incident Room copilot API: contextual chat, bounded diagnostics and approval requests."""
from __future__ import annotations

import asyncio
import re
from datetime import datetime, timezone, timedelta
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import desc, select, text

from apps.api.incident_resources import load_decision_brief_for_incident
from apps.api.remediation import RemediationRequest, create_remediation_request
from apps.audit_service.postgres import PostgreSQLAuditStore
from apps.incident_copilot import (
    READ_ACTIONS, WRITE_SUGGESTIONS, append_turn, fallback_intent, history,
    llm_plan, vm_binding, vm_read, is_recovery_comparison_question, asks_for_recorded_errors, recorded_error_facts,
    recorded_error_answer, nginx_inspection_answer, merge_incident_evidence,
    unsupported_security_exclusion_claim,
)
from apps.orchestrator.dynamic_investigation import DynamicInvestigationPlanner
from apps.incident_elastic import (
    elastic_live_read, elastic_answer, stored_elastic_observations,
)
from apps.orchestrator.workflow_store import WorkflowCheckpointStore
from apps.incident_followup import persist_and_reassess
from apps.chat_answer_review import requests_vm_allowed_hosts, allowed_hosts_answer, review_answer_coherence, mismatched_answer_message
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
        "technical_investigation": {
            "stop_origin": redact((brief.get("technical_investigation") or {}).get("stop_origin") or {}),
            "cause_confirmed": ((brief.get("technical_investigation") or {}).get("rca") or {}).get("cause_confirmed") is True,
            "hypotheses": [{
                "title": redact_text(str(x.get("title") or ""))[:160],
                "check": redact_text(str(x.get("check") or ""))[:220],
                "evidence_refs": (x.get("supporting") or [])[:5],
            } for x in (((brief.get("technical_investigation") or {}).get("rca") or {}).get("likely_hypotheses") or [])[:5]],
            "domains": [{
                "key": x.get("key"), "status": x.get("status"),
                "result": redact_text(str(x.get("technical_result") or ""))[:230],
            } for x in ((brief.get("technical_investigation") or {}).get("domains") or [])[:10]],
        },

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
    from apps.context_service.knowledge_relevance import filter_service_knowledge
    scope, allowed = DynamicInvestigationPlanner._scope(context)
    if not allowed:
        return {"success": False, "status": "knowledge_scope_unavailable"}
    query = redact_text(f"{service} incident troubleshooting: {question}")[:420]
    try:
        docs = await asyncio.wait_for(
            KnowledgeRAGService().search(
                query, limit=12, scope_context=scope,
                incident_id=str(incident_id), phase="incident_copilot_followup",
            ), timeout=8.0,
        )
    except Exception:
        return {"success": False, "status": "knowledge_unavailable"}
    filtered, audit = filter_service_knowledge(
        docs, expected_service=service, purpose="incident_copilot",
    )
    return {"success": True,
            "status": "retrieved" if filtered else "filtered_empty" if audit["rejected_count"] else "empty",
            "knowledge_relevance": {"accepted": min(len(filtered), 3),
                                    "rejected": audit["rejected_count"],
                                    "rejected_sources": audit["rejected"]},
            "documents": [
                {"source_ref": str(item.get("source_id") or "")[:120],
                 "excerpt": redact_text(str(item.get("excerpt") or item.get("content") or ""))[:500]}
                for item in filtered[:3] if isinstance(item, dict) and item.get("source_id")
            ]}



# The Incident Room service-status card deliberately does not use an LLM or
# a Decision Brief snapshot. It separates *observed systemd state* from the
# original monitoring alert and from application-level readiness.
_STATUS_STATES = {"active", "failed", "inactive", "activating",
                  "deactivating", "reloading"}


def _observed_status(
    service: str, target: str, evidence: list[dict], events: list[dict],
) -> dict:
    """Newest attributable, read-only VM MCP observation; never trust Agent prose."""
    from apps.incident_vm_identity import normalized_service, _safe_target

    candidates = []
    expected = normalized_service(service)

    def append(raw, when, source, reference):
        if not isinstance(raw, dict) or raw.get("success") is not True:
            return
        if normalized_service(raw.get("service")) != expected:
            return
        if _safe_target(raw.get("target")) != target:
            return
        active = str(raw.get("active_state") or "").lower().strip()
        if active not in _STATUS_STATES:
            return
        sub = str(raw.get("sub_state") or "").lower().strip()[:60]
        result = str(raw.get("result") or "")[:60]
        if isinstance(when, datetime):
            at = when if when.tzinfo else when.replace(tzinfo=timezone.utc)
        else:
            try:
                at = datetime.fromisoformat(str(when or "").replace("Z", "+00:00"))
                if not at.tzinfo:
                    at = at.replace(tzinfo=timezone.utc)
            except (TypeError, ValueError):
                return
        state = ("running" if active == "active" and sub == "running"
                 else "active" if active == "active"
                 else "stopped" if active in {"failed", "inactive"}
                 else "transitioning")
        candidates.append((at, {
            "status": state, "active_state": active, "sub_state": sub,
            "result": result, "target": target, "service": expected,
            "observed_at": at.astimezone(timezone.utc).isoformat(),
            "source": source, "evidence_ref": str(reference or "")[:160],
            "verified_systemd_only": True,
        }))

    for row in evidence:
        if row.get("source") != "vm_mcp":
            continue
        raw = row.get("raw_data") or {}
        if isinstance(raw, dict) and raw.get("diagnostic") == "service_status":
            append(raw, row.get("created_at"), "vm_mcp_recorded", row.get("reference"))

    for event in events:
        metadata = event.get("metadata") or {}
        if not isinstance(metadata, dict):
            continue
        kind = event.get("event_type")
        if kind == "incident_copilot_read" and event.get("action") == "service_status":
            append(metadata.get("observation"), event.get("created_at"),
                   "vm_mcp_chat", "audit:" + str(event.get("event_id") or ""))
        elif kind == "incident_service_status_rechecked":
            if event.get("status") != "success":
                # Failed explicit recheck supersedes old success in the visible
                # card. Never show yesterday's Running as a successful recheck.
                try:
                    at = event["created_at"]
                    at = at if isinstance(at, datetime) else datetime.fromisoformat(
                        str(at).replace("Z", "+00:00"))
                    if not at.tzinfo:
                        at = at.replace(tzinfo=timezone.utc)
                except (ValueError, TypeError, KeyError):
                    continue
                candidates.append((at, {
                    "status": "unknown", "service": expected, "target": target,
                    "observed_at": at.astimezone(timezone.utc).isoformat(),
                    "source": "vm_mcp_recheck_failed",
                    "reason": str(metadata.get("reason") or "vm_mcp_unavailable")[:100],
                    "verified_systemd_only": False,
                }))
            else:
                append(metadata.get("observation"), event.get("created_at"),
                       "vm_mcp_recheck", "audit:" + str(event.get("event_id") or ""))

    if not candidates:
        return {"status": "unknown", "service": expected, "target": target,
                "observed_at": None, "source": "no_verified_observation",
                "verified_systemd_only": False}
    return max(candidates, key=lambda candidate: candidate[0])[1]


async def _incident_status_scope(db, incident_id):
    incident, checkpoint, evidence = await _scope(db, incident_id)
    context = incident_vm_context(getattr(incident, "context", None), checkpoint)
    diagnosis = vm_binding_diagnostic(incident.service, evidence, context)
    return incident, evidence, context, diagnosis


@router.get("/incidents/{incident_id}/service-status")
async def incident_service_status(
    incident_id: UUID,
    identity=Depends(require_permission("read:incident")),
):
    """Initial card state from durable VM/Audit evidence. Zero remote calls."""
    async with AsyncSessionLocal() as db:
        incident, evidence, _, diagnosis = await _incident_status_scope(db, incident_id)
        target = diagnosis.get("candidate")
        if not target:
            return {"status": "unknown", "service": str(incident.service or ""),
                    "observed_at": None, "source": "identity_unverified",
                    "reason": diagnosis["reason"], "verified_systemd_only": False}
        events = await PostgreSQLAuditStore(db).list(str(incident_id), 200)
        return _observed_status(incident.service, target, evidence, events)


@router.post(
    "/incidents/{incident_id}/service-status/recheck",
    dependencies=[Depends(rate_limiter_strict)],
)
async def recheck_incident_service_status(
    incident_id: UUID,
    identity=Depends(require_permission("read:incident")),
):
    """An explicit, authenticated read-only VM MCP status check (no LLM/write)."""
    async with AsyncSessionLocal() as db:
        incident, evidence, context, diagnosis = await _incident_status_scope(db, incident_id)
        if not diagnosis.get("candidate"):
            raise HTTPException(status_code=409, detail={
                "code": "service_status_identity_unverified",
                "reason": diagnosis.get("reason"),
            })
        binding, live = await resolve_vm_binding(
            incident.service, evidence, context, force_live=True,
        )
        observation = live.get("live_observation") if binding else None
        success = isinstance(observation, dict) and observation.get("success") is True
        when = datetime.now(timezone.utc)
        record = {
            "event_id": str(uuid4()), "event_type": "incident_service_status_rechecked",
            "actor": identity.subject, "incident_id": str(incident_id),
            "action": "service_status",
            "status": "success" if success else "unavailable",
            "metadata": redact({
                "observation": observation if success else None,
                "reason": None if success else str(live.get("status") or "vm_mcp_unavailable"),
                "source_refs": (binding or {}).get("evidence_refs") or [],
            }),
            "created_at": when.isoformat(),
        }
        await PostgreSQLAuditStore(db).append(record)
        if success:
            checked = _observed_status(incident.service, binding["target"], [], [record])
            # Read-only rechecks may reconcile a *verified systemd Service Down*
            # incident, but never infer that a missing Zabbix webhook arrived.
            # Two independent live reads and a clean nginx validator are
            # required before recording local, non-monitor recovery.
            from apps.incident_service.service_recovery_reconciliation import (
                local_recovery_decision,
            )
            from integrations.vm.mcp_client import VMEdgeMCPClient
            from domain.models import IncidentStatus
            verdict = "service_not_running"
            if checked.get("status") == "running":
                await asyncio.sleep(1.0)
                client = VMEdgeMCPClient()
                try:
                    second = await client.service_status(binding["target"], incident.service)
                except Exception:
                    second = None
                vendor_valid = None
                if (isinstance(second, dict) and second.get("success") is True
                        and str(incident.service).lower().removesuffix(".service") == "nginx"):
                    try:
                        vendor = await client.config_validate(binding["target"], incident.service)
                        vendor_valid = (
                            vendor.get("success") is True
                            and vendor.get("supported") is True
                            and vendor.get("valid") is True
                        )
                    except Exception:
                        vendor_valid = False
                verdict = local_recovery_decision(
                    source=str(incident.source or ""),
                    summary=str(incident.summary or ""),
                    service=str(incident.service or ""),
                    context=incident.context or {},
                    first=observation, second=second,
                    target=binding["target"], vendor_syntax_ok=vendor_valid,
                )
                # A read:incident viewer may inspect live status, but only
                # an operator/SRE can authorize the side effect of resolving
                # an incident and revoking other pending approvals.
                from apps.incident_service.service_recovery_reconciliation import (
                    can_finalize_independent_recovery,
                )
                can_reconcile = can_finalize_independent_recovery(identity.roles)
                if verdict == "independent_vm_verified" and not can_reconcile:
                    verdict = "recovery_authorization_required"
                if verdict == "independent_vm_verified":
                    current = (await db.execute(
                        select(Incident).where(Incident.id == incident_id).with_for_update()
                    )).scalar_one()
                    current_ctx = dict(current.context or {})
                    # The latest incident may have already recovered or gained
                    # correlated signals while remote checks were running.
                    verdict = local_recovery_decision(
                        source=str(current.source or ""),
                        summary=str(current.summary or ""),
                        service=str(current.service or ""),
                        context=current_ctx,
                        first=observation, second=second,
                        target=binding["target"], vendor_syntax_ok=vendor_valid,
                    )
                    if verdict == "independent_vm_verified" and (
                            current.status not in {IncidentStatus.CLOSED, IncidentStatus.RESOLVED}):
                        from apps.incident_service.service_recovery_reconciliation import (
                            commit_independent_recovery,
                        )
                        try:
                            await commit_independent_recovery(
                                db, incident=current, target=binding["target"],
                                actor=identity.subject,
                                recovery_source="vm_mcp_systemd_recheck",
                                vendor_syntax_ok=vendor_valid,
                            )
                        except Exception:
                            await db.rollback()
                            verdict = "recovery_commit_unavailable"
                            from domain.contracts.logging import logger
                            logger.warning(
                                "independent_recovery_commit_failed",
                                incident_id=str(incident_id),
                                service=str(current.service),
                            )
            checked["recovery_verification"] = verdict
            checked["monitor_recovery_confirmed"] = bool(
                (incident.context or {}).get("source_recovery", {}).get("incident_resolved"))
            checked["incident_status"] = (
                "resolved" if verdict == "independent_vm_verified"
                else getattr(incident.status, "value", incident.status)
            )
            return checked
        return {"status": "unknown", "service": str(incident.service or ""),
                "target": diagnosis["candidate"], "observed_at": when.isoformat(),
                "source": "vm_mcp_recheck_failed",
                "reason": str(live.get("status") or "vm_mcp_unavailable"),
                "verified_systemd_only": False}


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
    ctx = incident_vm_context(getattr(incident, "context", None), checkpoint)
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
        vm_context = incident_vm_context(getattr(incident, "context", None), checkpoint)
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
        if requests_vm_allowed_hosts(payload.message):
            # A policy inventory request does not select an incident VM.
            # Restrict to SRE and never persist host names in shared history.
            roles = tuple(getattr(identity, "roles", ()) or ())
            persian = bool(re.search(r"[\u0600-\u06ff]", payload.message))
            answer = allowed_hosts_answer(roles, persian=persian)
            from integrations.llm.openai_compatible import configured_llm_adapter
            await review_answer_coherence(
                configured_llm_adapter, question=payload.message,
                answer="The requested allowlisted host inventory was handled "
                       "under server-side access control; no VM connection ran.",
                stage="incident_chat_answer_review",
            )
            audit_id = await append_turn(
                audit, incident_id=str(incident_id), actor=identity.subject,
                role="assistant", message="درخواست فهرست میزبان‌ها با بررسی نقش پاسخ داده شد؛ "
                "جزئیات زیرساخت در تاریخچهٔ مشترک رخداد ثبت نشده است.",
                model_status="policy_inventory",
                answer_basis="role_scoped_configuration",
            )
            return {
                "id": audit_id, "incident_id": str(incident_id),
                "kind": "answer", "message": answer, "proposal": None,
                "source_refs": [], "observation": None,
                "model_status": "policy_inventory",
                "answer_basis": "role_scoped_configuration",
            }
        plan = await llm_plan(payload.message, summary, previous)
        requested = fallback_intent(payload.message)
        historical_errors = asks_for_recorded_errors(payload.message)
        intent = "answer" if historical_errors else plan["intent"]
        # A comparison or diagnostic question must remain non-executing even
        # when the model/classifier notices the word "restart" or "start".
        explanation_only = is_recovery_comparison_question(payload.message)
        if explanation_only:
            intent = "answer"
        elif intent in WRITE_SUGGESTIONS and requested not in WRITE_SUGGESTIONS:
            # A model may discuss an action but cannot create an actionable
            # proposal unless the operator deliberately requested that action.
            intent = "answer"
        # Explicit action/read requests must not be ignored by a model's
        # free-form answer; model suggestions are otherwise advisory only.
        if requested in WRITE_SUGGESTIONS and not explanation_only:
            # An explicit operator Start/Restart/Reload always takes
            # precedence over a different action proposed by an LLM.
            intent = requested
        elif requested in {"elastic_logs", "elastic_recorded"}:
            # Never let a model convert an ELK question to a VM journal read
            # or invent an Elastic result from unrelated diagnostics.
            intent = requested
        elif requested in READ_ACTIONS and not historical_errors:
            # Explicit read instructions outrank a mismatching model guess.
            intent = requested
        elif requested == "nginx_config_inspect" and not historical_errors:
            # An explicit request to inspect files must not become a vague
            # no-access model answer or an unrelated diagnostic.
            intent = requested
        elif requested != "answer" and intent == "answer" and not explanation_only:
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
        followup_integration = None
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
            # Only actual, authenticated, successful live MCP diagnostics
            # qualify as new operational evidence. Historical Elastic results,
            # Cognia retrieval and free-form LLM prose remain auxiliary.
            if (
                observation and observation.get("success") is True
                and intent in (vm_actions | {"elastic_logs"})
            ):
                followup_integration = await persist_and_reassess(
                    db, incident_id=incident_id,
                    incident_service=str(incident.service or ""),
                    checkpoint=checkpoint, action=intent,
                    observation=observation, binding=binding,
                    actor=identity.subject, incident_evidence=evidence,
                )
                if followup_integration.get("evidence_ref"):
                    refs = list(dict.fromkeys(
                        refs + [followup_integration["evidence_ref"]]
                    ))[:12]
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
                if intent == "service_config_llm_repair":
                    state = str(observation.get("status") or "unavailable")[:80]
                    file_path = str(observation.get("config_file") or "نامشخص")[:240]
                    parts = ["درخواست تحلیل کامل فایل کانفیگ با LLM: " + file_path]
                    if observation.get("llm_received_complete_file"):
                        parts.append("تمام محتوای فایل انتخاب‌شده به LLM مورداعتماد ارسال شد.")
                    else:
                        parts.append("فایل کامل به مدل ارسال نشده است.")
                    if state == "llm_candidate_proposed" and observation.get("candidate_hash"):
                        parts.append("مدل نسخهٔ کامل اصلاح‌شده را برگرداند و تغییرات محدود پذیرفته شد.")
                        parts.append("تعداد خطوط تغییرکرده: " +
                                     str(observation.get("changed_line_count") or 0))
                        parts.append("شماره خطوط تغییرکرده: " +
                                     ", ".join(map(str, (observation.get("changed_line_numbers") or [])[:12])))
                        parts.append("SHA-256 نسخه پیشنهادی: " +
                                     str(observation.get("candidate_hash"))[:64])
                    else:
                        parts.append("نسخه اصلاح‌شدهٔ قابل‌قبول دریافت نشد؛ وضعیت: " + state)
                        if observation.get("rejection_reason"):
                            parts.append("علت رد: " +
                                         str(observation["rejection_reason"])[:80])
                    parts.append("این فقط پیش‌نمایش است. فایل اصلی تغییر نکرده، "
                                 "Candidate ذخیره و توسط Validator مستقل تأیید نشده "
                                 "و هنوز امکان Approval یا Apply ندارد.")
                    answer = "\n".join(parts)
                if intent == "service_config_review":
                    review = observation.get("model_syntax_review") or {}
                    file_path = str(observation.get("config_file") or "نامشخص")[:240]
                    stage = str(review.get("status") or "unavailable")
                    parts = ["بررسی فایل کانفیگ واقعی: " + file_path]
                    for label, field in (("تشخیص اولیه LLM", "model_diagnosis"),
                                         ("بازبینی دوم LLM", "model_second_review")):
                        item = review.get(field)
                        if isinstance(item, dict):
                            category = str(item.get("error_kind") or "نامشخص")[:48]
                            line = item.get("line")
                            reason = redact_text(str(item.get("reason") or ""))[:300]
                            suggestion = redact_text(str(item.get("suggestion") or ""))[:300]
                            parts.append(label + ": " + category +
                                         (", خط " + str(line) if type(line) is int else "") +
                                         ". " + reason + " پیشنهاد: " + suggestion)
                    if not any(isinstance(review.get(k), dict) for k in
                               ("model_diagnosis", "model_second_review")):
                        parts.append("مدل نتوانست بررسی معتبر انجام دهد (" + stage[:65] + ").")
                    multi = observation.get("file_model_reviews") or []
                    for entry in multi[:4]:
                        if (not isinstance(entry, dict) or
                                entry.get("path") == observation.get("config_file")):
                            continue
                        other = entry.get("review") or {}
                        diagnosis = other.get("model_diagnosis") or {}
                        parts.append("فایل بررسی‌شده دیگر: " +
                                     str(entry.get("path") or "")[:220] +
                                     " — تشخیص LLM: " +
                                     str(diagnosis.get("error_kind") or other.get("status") or
                                         "نامشخص")[:90])
                    if observation.get("candidate_hash"):
                        parts.append("پیشنهاد اصلاح قطعیِ محدود، Hash نسخه پیشنهادی: " +
                                     str(observation["candidate_hash"])[:64])
                    parts.append("LLM فقط بررسی مشورتی انجام داده است؛ اعتبارسنجی مستقل "
                                 "نسخهٔ موقت، پیش‌شرط Approval است و تا اینجا فایل اصلی تغییر نکرده است.")
                    answer = "\n".join(parts)
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
                if observation.get("binding_reason"):
                    reason += "/" + str(observation["binding_reason"])[:65]
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
                original_action = action
                if action == "start_service" and binding.get("active_state") == "failed":
                    # The registered runbook maps failed units to Restart.
                    # Present the changed action for deliberate operator review.
                    action = "restart_service"
                    explanation = (
                        "وضعیت زنده سرویس failed است. Runbook برای این حالت Restart "
                        "را تعریف کرده، نه Start؛ برای ادامه درخواست تأیید Restart را انتخاب کنید."
                    )
                else:
                    explanation = f"درخواست {action} برای همین سرویس آمادهٔ بررسی است."
                proposal = {
                    "action": action, "requested_action": original_action,
                    "service": binding["service"], "target": binding["target"],
                    "risk_level": "high",
                    "status": "requires_preflight_and_approval",
                    "execution_authority": False,
                }
                answer = explanation + (
                    "\nهنوز عملیاتی اجرا نشده است. برای ایجاد درخواست تأیید، "
                    "باید پیش‌شرط‌های زندهٔ Runbook نیز عبور کنند."
                )
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
        if followup_integration and followup_integration.get("evidence_ref"):
            phase = followup_integration.get("status")
            if phase == "reassessed_read_only":
                note = (
                    "این نتیجه به شواهد رخداد اضافه و تحلیل ایجنت‌ها و ارزیابی تصمیم "
                    "بدون اجرای عملیات دوباره محاسبه شد."
                )
            else:
                note = (
                    "شاهد جدید در تاریخچه پایدار رخداد ثبت شد؛ تحلیل مجدد هنوز "
                    "تکمیل یا مجاز نشده است (" + str(phase)[:90] + ")."
                )
            kb = followup_integration.get("knowledge") or {}
            if kb.get("status") == "pending_review":
                note += " پیش‌نویس دانش Cognia در صف بازبینی انسانی ایجاد شد و هنوز منتشر نشده است."
            answer += "\n\n" + note
        from integrations.llm.openai_compatible import configured_llm_adapter
        verdict, _ = await review_answer_coherence(
            configured_llm_adapter,
            question=payload.message,
            answer=answer,
            stage="incident_chat_answer_review",
        )
        if verdict == "mismatch" and kind == "answer":
            answer = mismatched_answer_message(
                payload.message,
                persian=bool(re.search(r"[\u0600-\u06ff]", payload.message)),
            )
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
        "followup_integration": followup_integration,
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
        context = incident_vm_context(getattr(incident, "context", None), checkpoint)
        binding, diagnosis = await resolve_vm_binding(
            incident.service, evidence, context, force_live=True,
        )
        if binding is None:
            raise HTTPException(status_code=409, detail={
                "code": "incident_vm_identity_unverified",
                "reason": diagnosis.get("status"),
            })
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
                "diagnostics_checked": [
                    item.get("raw_data", {}).get("diagnostic")
                    for item in snapshot.get("evidence") or []
                    if isinstance(item, dict) and isinstance(item.get("raw_data"), dict)
                ],
                "validation_scope": preflight.get("validation_scope"),
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
                "preflight_validation_scope": preflight.get("validation_scope"),
                "configuration_semantics_valid": preflight.get("configuration_semantics_valid"),
                "execution_authority": False,
            },
            "created_at": datetime.now(timezone.utc).isoformat(),
        })
    return {
        "status": "pending_approval", "approval_id": str(approved_request["approval_id"]),
        "action": action, "target": binding["target"], "service": binding["service"],
        "executed": False,
    }
