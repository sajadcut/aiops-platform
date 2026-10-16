"""Fail-closed proactive prevalidation for an evidence-bound config microfix.

The automation MAY register an immutable pending_validation request and
perform read-only staged validation. It may NEVER approve, sign, consume,
restart a service, or apply a change. No candidate = no execution request.
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from uuid import UUID, uuid4

from sqlalchemy import text

from apps.api.config_change_review import ConfigReviewResponse, _matching_proposal
from apps.api.config_change_execution import validate_config_ticket
from apps.approval_service.binding import bind_metadata
from apps.approval_service.postgres import PostgreSQLApprovalStore
from apps.incident_vm_identity import incident_vm_context, vm_binding_diagnostic
from apps.audit_service.postgres import PostgreSQLAuditStore
from domain.contracts.logging import logger
from domain.models import Incident
from integrations.vm.mcp_client import VMEdgeMCPClient


async def _verified_service_start_scope(*, target: str, service: str) -> bool:
    """Only a fresh read-only VM MCP check can extend a new ticket to Start.

    This does NOT approve or execute a service operation. The exact Boolean
    goes into the immutable approval digest and signed single-use claim.
    Older config-only tickets must never be upgraded.
    """
    try:
        status = await asyncio.wait_for(
            VMEdgeMCPClient().service_status(target, service), timeout=12,
        )
    except Exception as exc:
        logger.warning(
            "config_recovery_scope_precheck_unavailable",
            service=service, failure_type=type(exc).__name__,
        )
        return False
    if not isinstance(status, dict):
        return False
    observed = str(status.get("service") or "").lower().removesuffix(".service")
    requested = str(service).lower().removesuffix(".service")
    active = status.get("active_state")
    sub = status.get("sub_state")
    return bool(
        status.get("success") is True
        and status.get("target") == target
        and observed == requested
        and status.get("load_state") == "loaded"
        and ((active == "failed" and sub == "failed")
             or (active == "inactive" and sub == "dead"))
    )


def auto_queue_candidate(state: dict) -> dict | None:
    """Only existing, tightly validated hash-bound proposals can enter queue."""
    if state.get("approval") or state.get("execution_result"):
        return None
    proposal = ((state.get("context") or {})
                .get("dynamic_investigation") or {}).get("config_proposal") or {}
    if not isinstance(proposal, dict):
        return None
    try:
        payload = ConfigReviewResponse(
            decision="request_isolated_validation",
            expected_original_sha256=str(proposal.get("original_sha256") or ""),
            expected_candidate_sha256=str(proposal.get("candidate_sha256") or ""),
            start_service_after_apply=False,
        )
    except Exception:
        return None
    return proposal if _matching_proposal(proposal, payload) else None


async def auto_queue_prevalidation(session, incident_id: str, state: dict) -> dict:
    """Automatic *request*, never automatic Approval; record the exact blocker."""
    proposal = auto_queue_candidate(state)
    if (proposal is None and not state.get("approval")
            and not state.get("execution_result")):
        # Recover from an orchestration handoff dropping a valid worker
        # candidate. Independently recompute the contract from the CURRENT
        # verified MCP evidence, never from model text, old UI state or
        # an operator-supplied file path.
        context = state.get("context") or {}
        evidence = context.get("evidence") or []
        if any(
            isinstance(item, dict) and item.get("source") == "vm_mcp"
            and isinstance(item.get("raw_data"), dict)
            and item["raw_data"].get("diagnostic") == "service_config_review"
            and item["raw_data"].get("success") is True
            and item["raw_data"].get("status") == "candidate_proposed"
            for item in evidence
        ):
            try:
                from apps.orchestrator.dynamic_investigation import (
                    DynamicInvestigationPlanner,
                )
                recalculated = await DynamicInvestigationPlanner.propose(
                    state, adapter=None,
                )
                recovered = recalculated.get("config_proposal")
                if isinstance(recovered, dict):
                    current = context.get("dynamic_investigation") or {}
                    context["dynamic_investigation"] = {
                        **current, "config_proposal": recovered,
                    }
                    proposal = auto_queue_candidate(state)
            except Exception as exc:
                logger.warning(
                    "config_candidate_recalculation_failed",
                    incident_id=str(incident_id),
                    error_type=type(exc).__name__,
                )
    if proposal is None:
        # A generic "no_verified_candidate" hid the exact reason and forced
        # operators to repeat lengthy LLM attempts. Publish only bounded
        # control-state enums: never config content, LLM text or hashes.
        investigation = ((state.get("context") or {})
                         .get("dynamic_investigation") or {})
        candidate = investigation.get("config_proposal") or {}
        if state.get("approval") or state.get("execution_result"):
            reason = "existing_workflow_action"
        elif not candidate:
            reason = "no_config_proposal"
        elif candidate.get("status") != "candidate_proposed":
            reason = "candidate_not_parser_valid"
        else:
            reason = "candidate_contract_rejected"
        return {"status": "no_verified_candidate", "reason": reason,
                "approval_id": None, "production_write_performed": False}
    incident = await session.get(Incident, UUID(str(incident_id)))
    if incident is None or str(incident.service or "").lower().removesuffix(".service") != str(
        proposal["service"]).lower().removesuffix(".service"):
        return {"status": "incident_binding_unverified"}
    checkpoint = {"state": state}
    evidence = list((state.get("context") or {}).get("evidence") or [])
    binding = vm_binding_diagnostic(
        proposal["service"], evidence, incident_vm_context(incident.context, checkpoint),
    )
    target = binding.get("candidate")
    if not target:
        return {"status": "vm_binding_unverified", "reason": binding.get("reason")}
    audit = PostgreSQLAuditStore(session)
    previous = await audit.list(str(incident_id), 150)
    if any(
        event.get("event_type") == "config_change_review_response"
        and event.get("status") == "declined"
        and (event.get("metadata") or {}).get("candidate_sha256") == proposal["candidate_sha256"]
        for event in previous
    ):
        return {"status": "previously_declined"}
    prior_id = (await session.execute(text("""
        SELECT approval_id FROM approvals
        WHERE incident_id=:incident_id AND action='apply_configuration_change'
          AND metadata->>'original_sha256'=:original
          AND metadata->>'candidate_sha256'=:candidate
        LIMIT 1
    """), {"incident_id": str(incident_id),
           "original": proposal["original_sha256"],
           "candidate": proposal["candidate_sha256"]})).scalar_one_or_none()
    if prior_id:
        return {"status": "already_queued", "approval_id": str(prior_id)}
    # Read the *current* systemd state before fixing the approval scope.
    # The operator's later high-risk Approval explicitly covers this start;
    # automatic prevalidation alone has no production-write authority.
    start_after_apply = await _verified_service_start_scope(
        target=target, service=proposal["service"],
    )
    parameters = {
        "service": proposal["service"],
        "config_file": proposal["config_file"],
        "original_sha256": proposal["original_sha256"],
        "candidate_sha256": proposal["candidate_sha256"],
        "proposed_change": proposal["proposed_change"],
        "start_service_after_apply": start_after_apply,
    }
    metadata = bind_metadata(
        {"workflow": "config_change", **parameters,
         "source_evidence_refs": proposal["source_evidence_refs"][:8],
         "request_phase": "pending_validation",
         "automated_prevalidation": True,
         "start_service_after_apply": start_after_apply,
         "isolated_validation": False,
         "production_write_performed": False},
        incident_id=str(incident_id), tool_name="vm_config_change",
        action="apply_configuration_change", target=target,
        parameters=parameters, timeout=30, runbook_id="vm-config-change",
        runbook_version="1", rollback=False,
    )
    ticket = await PostgreSQLApprovalStore(session).save_validation_request({
        "approval_id": str(uuid4()), "incident_id": str(incident_id),
        "action": "apply_configuration_change",
        # A queue initiator is not an approver; pending_validation is
        # non-approvable until the *separate* isolated validator passes.
        "approver": "aiops-auto-prevalidation",
        "metadata": metadata, "created_at": datetime.now(timezone.utc),
    })
    await audit.append({
        "event_id": str(uuid4()), "event_type": "config_auto_prevalidation_queued",
        "actor": "aiops-auto-prevalidation", "incident_id": str(incident_id),
        "action": "configuration_review", "status": "pending_validation",
        "metadata": {
            "approval_id": str(ticket["approval_id"]),
            "original_sha256": proposal["original_sha256"],
            "candidate_sha256": proposal["candidate_sha256"],
            "config_file": proposal["config_file"],
            "proposed_change": proposal["proposed_change"],
            "production_write_performed": False,
            "human_approval_required": True,
            "start_service_after_apply": start_after_apply,
        },
        "created_at": datetime.now(timezone.utc).isoformat(),
    })
    # The independent stage validates, but cannot execute production writes.
    # Timeouts leave the request visibly pending_validation, never PASS.
    try:
        checked = await asyncio.wait_for(
            validate_config_ticket(str(ticket["approval_id"]),
                                   actor="aiops-auto-prevalidation"),
            timeout=45,
        )
        return {"status": str(checked.get("status") or "pending_validation"),
                "approval_id": str(ticket["approval_id"]),
                "validation": str(checked.get("validation") or "unverified")}
    except Exception as exc:
        logger.warning(
            "config_auto_prevalidation_pending",
            incident_id=str(incident_id),
            approval_id=str(ticket["approval_id"]),
            failure_type=type(exc).__name__,
        )
        return {"status": "pending_validation",
                "approval_id": str(ticket["approval_id"]),
                "validation": "blocked_or_unavailable"}
