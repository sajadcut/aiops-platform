from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import desc, select, text

from apps.approval_service.postgres import PostgreSQLApprovalStore
from apps.audit_service import AuditService
from apps.audit_service.postgres import PostgreSQLAuditStore
from apps.orchestrator.runtime import DurableWorkflowRuntime
from apps.security.auth import require_permission
from database import AsyncSessionLocal
from domain.contracts.context import get_trace_id
from domain.contracts.rate_limit import rate_limiter_default, rate_limiter_strict
from domain.models import Finding, Incident, IncidentStatus
from domain.schemas import IncidentCreate, IncidentResponse

router = APIRouter()


class RemediationRequest(BaseModel):
    reason: str = Field(default="Operator requested incident remediation")
    risk_level: str = Field(default="medium")
    approver: str = Field(default="Team-Lead")


async def _load_incident(db, incident_id: UUID) -> Incident:
    incident = await db.get(Incident, incident_id)
    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    return incident


@router.post(
    "/incidents",
    response_model=IncidentResponse,
    status_code=201,
    dependencies=[Depends(rate_limiter_default)],
)
async def create_incident(
    incident_data: IncidentCreate,
    _user=Depends(require_permission("read:incident")),
):
    async with AsyncSessionLocal() as db:
        incident = Incident(
            id=uuid4(),
            source=incident_data.source,
            severity=incident_data.severity,
            service=incident_data.service,
            summary=incident_data.summary,
            context=incident_data.context or {},
            status=IncidentStatus.OPEN,
        )
        db.add(incident)
        await db.commit()
        await db.refresh(incident)

        AuditService.record(
            "incident_created",
            "api",
            str(incident.id),
            None,
            "recorded",
            {"source": incident.source, "severity": incident.severity, "service": incident.service},
        )
        await AuditService.flush_to_store(PostgreSQLAuditStore(db), incident_id=str(incident.id))
        return incident


@router.get("/incidents/{incident_id}")
async def get_incident(
    incident_id: UUID,
    _user=Depends(require_permission("read:incident")),
):
    async with AsyncSessionLocal() as db:
        incident = await _load_incident(db, incident_id)
        return IncidentResponse.model_validate(incident)


@router.post(
    "/incidents/{incident_id}/analyze",
    dependencies=[Depends(rate_limiter_strict)],
)
async def analyze_incident_by_id(
    request: Request,
    incident_id: UUID,
    _user=Depends(require_permission("read:incident")),
):
    async with AsyncSessionLocal() as db:
        incident = await _load_incident(db, incident_id)
        from apps.context_service import ContextBuilder

        input_data = IncidentCreate(
            source=incident.source,
            severity=incident.severity,
            service=incident.service,
            summary=incident.summary,
            context=incident.context or {},
        )
        full_context = await ContextBuilder().build_context(input_data)
        initial_state: Dict[str, Any] = {
            "incident_id": str(incident.id),
            "evidence_summary": incident.summary or f"Operational incident for {incident.service or 'unknown'}",
            "service_name": incident.service,
            "context": full_context,
            "messages": [],
            "findings": [],
            "confidence": 0.0,
        }
        result = await DurableWorkflowRuntime(db).start(initial_state)
        return {
            "status": "success",
            "incident_id": str(incident.id),
            "context": result.get("context", {}),
            "live_evidence": result.get("live_evidence", {}),
            "rag_results": result.get("knowledge_results", []),
            "similar_incidents": result.get("memory_results", []),
            "analysis": {
                "triage_result": result.get("triage_result"),
                "analysis_results": result.get("analysis_results", []),
                "final_plan": result.get("final_plan"),
                "messages": result.get("messages", []),
                "findings": result.get("findings", []),
            },
            "evaluation": result.get("evaluation"),
            "decision": result.get("decision"),
            "approval": result.get("approval"),
            "execution": result.get("execution_result"),
            "verification": result.get("verification_result"),
            "trace_id": get_trace_id(),
        }


@router.post("/incidents/analyze", dependencies=[Depends(rate_limiter_strict)])
async def analyze_incident_legacy(
    request: Request,
    incident_data: IncidentCreate,
    _user=Depends(require_permission("read:incident")),
):
    async with AsyncSessionLocal() as db:
        incident = Incident(
            id=uuid4(),
            source=incident_data.source,
            severity=incident_data.severity,
            service=incident_data.service,
            summary=incident_data.summary,
            context=incident_data.context or {},
            status=IncidentStatus.OPEN,
        )
        db.add(incident)
        await db.commit()
        await db.refresh(incident)
        incident_id = incident.id

    return await analyze_incident_by_id(request, incident_id, _user)


@router.post("/incidents/{incident_id}/approve")
async def approve_incident(
    incident_id: UUID,
    _user=Depends(require_permission("approve:low_risk")),
):
    async with AsyncSessionLocal() as db:
        await _load_incident(db, incident_id)
        approval_id = (
            await db.execute(
                text(
                    "SELECT approval_id FROM approvals "
                    "WHERE incident_id=:incident_id AND status='pending' "
                    "ORDER BY created_at DESC LIMIT 1"
                ),
                {"incident_id": str(incident_id)},
            )
        ).scalar_one_or_none()
        if not approval_id:
            raise HTTPException(status_code=404, detail="No pending approval for incident")

        saved = await PostgreSQLApprovalStore(db).set_status(str(approval_id), "approved")
        if saved is None:
            raise HTTPException(status_code=404, detail="Approval not found")

        AuditService.record(
            "approval_granted",
            "api",
            str(incident_id),
            saved.get("action"),
            "approved",
            {"approval_id": str(approval_id)},
        )
        await AuditService.flush_to_store(PostgreSQLAuditStore(db), incident_id=str(incident_id))
        return saved


@router.post("/incidents/{incident_id}/execute")
async def execute_incident(
    incident_id: UUID,
    _user=Depends(require_permission("execute:approved")),
):
    async with AsyncSessionLocal() as db:
        await _load_incident(db, incident_id)
        runtime = DurableWorkflowRuntime(db)
        checkpoint = await runtime.checkpoints.load(str(incident_id))
        if not checkpoint:
            raise HTTPException(status_code=409, detail="No resumable workflow checkpoint for incident")

        approval = checkpoint.get("state", {}).get("approval") or {}
        approval_id = approval.get("approval_id")
        if not approval_id:
            raise HTTPException(status_code=409, detail="Incident has no approval gate")

        approval_record = await PostgreSQLApprovalStore(db).get(str(approval_id))
        if not approval_record or approval_record.get("status") != "approved":
            raise HTTPException(status_code=409, detail="Approval is not granted")

        try:
            result = await runtime.resume_after_approval(str(incident_id))
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc

        return {
            "incident_id": str(incident_id),
            "approval_id": str(approval_id),
            "execution": result.get("execution_result"),
            "verification": result.get("verification_result"),
            "memory": result.get("memory_results", []),
            "status": "completed",
        }


@router.post("/incidents/{incident_id}/remediate")
async def request_remediation(
    incident_id: UUID,
    payload: RemediationRequest,
    _user=Depends(require_permission("approve:low_risk")),
):
    async with AsyncSessionLocal() as db:
        incident = await _load_incident(db, incident_id)
        finding = (
            await db.execute(
                select(Finding)
                .where(Finding.incident_id == incident_id)
                .order_by(desc(Finding.created_at))
                .limit(1)
            )
        ).scalars().first()
        action = finding.statement if finding else f"Remediate incident for service {incident.service or 'unknown'}"
        approval_id = str(uuid4())
        record = {
            "approval_id": approval_id,
            "incident_id": str(incident_id),
            "action": action[:1000],
            "risk_level": payload.risk_level,
            "approver": payload.approver,
            "status": "pending",
            "metadata": {"source": "incident_api", "reason": payload.reason},
            "created_at": datetime.now(timezone.utc),
            "approved_at": None,
            "rejected_at": None,
        }
        saved = await PostgreSQLApprovalStore(db).save(record)
        AuditService.record(
            "remediation_requested",
            "api",
            str(incident_id),
            action,
            "pending_approval",
            {"approval_id": approval_id, "risk_level": payload.risk_level},
        )
        await AuditService.flush_to_store(PostgreSQLAuditStore(db), incident_id=str(incident_id))
        return saved