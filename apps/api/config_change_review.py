"""Human response to an incident configuration *proposal*, not deployment approval.

The response is durable/auditable and bound to the exact existing proposal
hashes. It cannot create an Approval, ExecutionRequest or bypass an isolated
validator; application of bytes needs a separate guarded implementation.
"""
from __future__ import annotations

import re
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select

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


def _matching_proposal(proposal: dict, payload: ConfigReviewResponse) -> bool:
    """Never accept hashes taken solely from a browser or free-form LLM."""
    return (
        proposal.get("status") == "candidate_proposed"
        and proposal.get("service") in {"nginx", "nginx.service"}
        and proposal.get("execution_authority") is False
        and proposal.get("apply_eligible") is False
        and _hash(proposal.get("original_sha256"))
        and _hash(proposal.get("candidate_sha256"))
        and payload.expected_original_sha256 == proposal.get("original_sha256")
        and payload.expected_candidate_sha256 == proposal.get("candidate_sha256")
    )


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
        events = await PostgreSQLAuditStore(db).list(str(incident_id), 150)
    for event in events:
        if event.get("event_type") != "config_change_review_response":
            continue
        meta = event.get("metadata") or {}
        if (isinstance(meta, dict)
                and meta.get("candidate_sha256") == proposal.get("candidate_sha256")
                and meta.get("original_sha256") == proposal.get("original_sha256")):
            return {
                "status": event.get("status"), "decision": meta.get("decision"),
                "candidate_sha256": meta.get("candidate_sha256"),
                "created_at": str(event.get("created_at")),
                "execution_authority": False,
            }
    return {"status": "not_responded", "execution_authority": False}


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
    return {
        "status": status, "decision": payload.decision,
        "candidate_sha256": payload.expected_candidate_sha256,
        "execution_authority": False,
        "production_write_performed": False,
    }
