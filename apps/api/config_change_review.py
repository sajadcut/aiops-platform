"""Human response to an incident configuration *proposal*, not deployment approval.

The response is durable/auditable and bound to the exact existing proposal
hashes. It cannot create an Approval, ExecutionRequest or bypass an isolated
validator; application of bytes needs a separate guarded implementation.
"""
from __future__ import annotations

import re
from datetime import datetime, timezone
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select, text

from apps.approval_service.binding import bind_metadata
from apps.approval_service.postgres import PostgreSQLApprovalStore
from apps.incident_vm_identity import incident_vm_context, vm_binding_diagnostic
from apps.audit_service import AuditService
from apps.audit_service.postgres import PostgreSQLAuditStore
from apps.orchestrator.workflow_store import WorkflowCheckpointStore
from apps.security.auth import require_permission
from database import AsyncSessionLocal
from domain.models import Incident


router = APIRouter()


class ConfigReviewResponse(BaseModel):
    decision: str
    expected_original_sha256: str
    expected_candidate_sha256: str


def _proposal(checkpoint: dict) -> dict:
    state = checkpoint.get("state") if isinstance(checkpoint, dict) else {}
    state = state if isinstance(state, dict) else {}
    context = state.get("context") or {}
    investigation = context.get("dynamic_investigation") or {}
    proposed = investigation.get("config_proposal") or {}
    if not isinstance(proposed, dict):
        return {}
    return proposed


def _hash(value: object) -> bool:
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None


_ALLOWED_CHANGES = frozenset({"remove_extra_opening_brace", "remove_trailing_json_comma"})


def _matching_proposal(proposal: dict, payload: ConfigReviewResponse) -> bool:
    """Accept only evidence-backed deterministic transformations."""
    service = str(proposal.get("service") or "").strip().lower().removesuffix(".service")
    filename = str(proposal.get("config_file") or "")
    change = proposal.get("proposed_change")
    compatible = (
        change == "remove_extra_opening_brace" and service == "nginx"
        and filename.endswith(".conf")
    ) or (
        change == "remove_trailing_json_comma" and filename.endswith(".json")
    )
    return (
        proposal.get("status") == "candidate_proposed"
        and bool(re.fullmatch(r"[a-z0-9@_.:-]{1,100}", service))
        and compatible and filename.startswith("/")
        and ".." not in filename.split("/")
        and change in _ALLOWED_CHANGES
        and bool(proposal.get("source_evidence_refs"))
        and proposal.get("execution_authority") is False
        and proposal.get("apply_eligible") is False
        and _hash(proposal.get("original_sha256"))
        and _hash(proposal.get("candidate_sha256"))
        and payload.expected_original_sha256 == proposal.get("original_sha256")
        and payload.expected_candidate_sha256 == proposal.get("candidate_sha256")
    )


def _approval_for_proposal(approval: dict, proposal: dict) -> bool:
    meta = approval.get("metadata") or {}
    return (approval.get("action") == "apply_configuration_change"
            and isinstance(meta, dict)
            and meta.get("original_sha256") == proposal.get("original_sha256")
            and meta.get("candidate_sha256") == proposal.get("candidate_sha256")
            and meta.get("service") == proposal.get("service")
            and meta.get("config_file") == proposal.get("config_file"))


def _review_progress(*, status: str, decision: str | None, proposal: dict,
                     created_at: str | None = None,
                     approval: dict | None = None) -> dict:
    """Expose durable intent separately from executable Approval authority.

    A recorded request is NOT a scheduled validator job. Only an isolated
    successful validation and an independently registered apply contract
    could allow creation of an executable change Approval.
    """
    requested = status in {"awaiting_isolated_validation", "pending_validation"}
    queue_status = str(approval.get("status")) if approval else "not_created"
    return {
        "status": status,
        "decision": decision,
        "service": proposal.get("service"),
        "config_file": proposal.get("config_file"),
        "original_sha256": proposal.get("original_sha256"),
        "candidate_sha256": proposal.get("candidate_sha256"),
        "created_at": created_at,
        "request_recorded": requested,
        "validation_status": proposal.get("validation_status") or "UNVERIFIED",
        "validation_pipeline_status": "not_implemented",
        "change_contract_status": "not_implemented",
        "approval_status": queue_status,
        "approval_id": str(approval["approval_id"]) if approval else None,
        "approval_queue_registered": bool(approval),
        "approval_eligible": False,
        "approval_actionable": False,
        "execution_authority": False,
        "production_write_performed": False,
        "blocking_reasons": [
            "isolated_candidate_validation_not_implemented",
            "versioned_file_apply_contract_not_implemented",
            "executable_approval_not_created",
        ] if requested else [],
    }


@router.get("/incidents/{incident_id}/configuration-review-response")
async def get_config_review_response(
    incident_id: UUID,
    identity=Depends(require_permission("read:incident")),
):
    async with AsyncSessionLocal() as db:
        if await db.get(Incident, incident_id) is None:
            raise HTTPException(status_code=404, detail="incident_not_found")
        checkpoint = await WorkflowCheckpointStore(db).load(str(incident_id)) or {}
        proposal = _proposal(checkpoint)
        match = (await db.execute(text("""
            SELECT approval_id FROM approvals
            WHERE incident_id=:incident_id
              AND action='apply_configuration_change'
              AND metadata->>'original_sha256'=:source
              AND metadata->>'candidate_sha256'=:candidate
            LIMIT 1
        """), {
            "incident_id": str(incident_id),
            "source": proposal.get("original_sha256") or "",
            "candidate": proposal.get("candidate_sha256") or "",
        })).scalar_one_or_none()
        approval = await PostgreSQLApprovalStore(db).get(str(match)) if match else None
        if approval and _approval_for_proposal(approval, proposal):
            return _review_progress(
                status=approval["status"], decision="request_change_approval",
                proposal=proposal, created_at=str(approval.get("created_at")),
                approval=approval,
            )
        events = await PostgreSQLAuditStore(db).list(str(incident_id), 150)
    for event in events:
        if event.get("event_type") != "config_change_review_response":
            continue
        meta = event.get("metadata") or {}
        if (isinstance(meta, dict)
                and meta.get("candidate_sha256") == proposal.get("candidate_sha256")
                and meta.get("original_sha256") == proposal.get("original_sha256")):
            return _review_progress(
                status=str(event.get("status") or "not_responded"),
                decision=meta.get("decision"),
                proposal=proposal,
                created_at=str(event.get("created_at")),
            )
    return _review_progress(status="not_responded", decision=None, proposal=proposal)


@router.post("/incidents/{incident_id}/configuration-review-response")
async def post_config_review_response(
    incident_id: UUID,
    payload: ConfigReviewResponse,
    identity=Depends(require_permission("approve:high_risk")),
):
    if payload.decision not in {"request_isolated_validation", "reject"}:
        raise HTTPException(status_code=422, detail="unsupported_config_review_decision")
    async with AsyncSessionLocal() as db:
        if await db.get(Incident, incident_id) is None:
            raise HTTPException(status_code=404, detail="incident_not_found")
        checkpoint = await WorkflowCheckpointStore(db).load(str(incident_id)) or {}
        proposal = _proposal(checkpoint)
        if not _matching_proposal(proposal, payload):
            raise HTTPException(status_code=409, detail="stale_or_unverified_config_proposal")
        audit = PostgreSQLAuditStore(db)
        previous = await audit.list(str(incident_id), 150)
        for event in previous:
            meta = event.get("metadata") or {}
            if (event.get("event_type") == "config_change_review_response"
                    and isinstance(meta, dict)
                    and meta.get("candidate_sha256") == payload.expected_candidate_sha256
                    and meta.get("original_sha256") == payload.expected_original_sha256):
                raise HTTPException(status_code=409, detail="proposal_already_reviewed")
        status = (
            "awaiting_isolated_validation"
            if payload.decision == "request_isolated_validation" else "declined"
        )
        AuditService.record(
            "config_change_review_response", identity.subject,
            str(incident_id), "nginx_configuration_review", status,
            {
                "decision": payload.decision,
                "original_sha256": payload.expected_original_sha256,
                "candidate_sha256": payload.expected_candidate_sha256,
                "service": proposal.get("service"),
                "file": proposal.get("config_file"),
                "review_only": True, "production_write_performed": False,
            },
        )
        await AuditService.flush_to_store(audit, incident_id=str(incident_id))
    return _review_progress(
        status=status, decision=payload.decision, proposal=proposal,
    )
