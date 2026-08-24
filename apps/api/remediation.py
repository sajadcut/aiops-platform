from __future__ import annotations

from typing import Any, Dict
from uuid import UUID, uuid4
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from apps.approval_service.postgres import PostgreSQLApprovalStore
from apps.audit_service import AuditService
from apps.execution_service import ExecutionRequest, ExecutionService
from apps.security.auth import require_permission
from database import AsyncSessionLocal
from domain.models import Incident, Finding
from sqlalchemy import desc, select

router = APIRouter()


class RemediationRequest(BaseModel):
    target: str = Field(min_length=1)
    service: str = Field(min_length=1)
    action: str = Field(default="restart_service")
    dry_run: bool = False
    reason: str | None = None


@router.post("/incidents/{incident_id}/remediation-requests")
async def create_remediation_request(
    incident_id: UUID,
    payload: RemediationRequest,
    _user=Depends(require_permission("approve:low_risk")),
):
    async with AsyncSessionLocal() as db:
        incident = await db.get(Incident, incident_id)
        if incident is None:
            raise HTTPException(status_code=404, detail="Incident not found")
        finding = (await db.execute(
            select(Finding).where(Finding.incident_id == incident_id).order_by(desc(Finding.created_at)).limit(1)
        )).scalars().first()

        approval_id = str(uuid4())
        record = {
            "approval_id": approval_id,
            "incident_id": str(incident_id),
            "action": payload.action,
            "risk_level": "high",
            "approver": "Team-Lead",
            "status": "pending",
            "metadata": {
                "tool_name": "ssh_vm",
                "target": payload.target,
                "service": payload.service,
                "dry_run": payload.dry_run,
                "reason": payload.reason,
                "finding": finding.statement if finding else None,
            },
            "created_at": datetime.now(timezone.utc).isoformat(),
            "approved_at": None,
            "rejected_at": None,
        }
        saved = await PostgreSQLApprovalStore(db).save(record)

    AuditService.record(
        "remediation_requested",
        "dashboard",
        str(incident_id),
        payload.action,
        "pending_approval",
        {"approval_id": approval_id, "target": payload.target, "service": payload.service},
    )
    return saved


@router.post("/approvals/{approval_id}/execute")
async def execute_approved_remediation(
    approval_id: str,
    _user=Depends(require_permission("execute:approved")),
):
    async with AsyncSessionLocal() as db:
        approval = await PostgreSQLApprovalStore(db).get(approval_id)
    if approval is None:
        raise HTTPException(status_code=404, detail="Approval not found")
    if approval.get("status") != "approved":
        raise HTTPException(status_code=409, detail="Approval is not approved")

    metadata: Dict[str, Any] = approval.get("metadata") or {}
    request = ExecutionRequest(
        tool_name=str(metadata.get("tool_name", "ssh_vm")),
        action=str(approval["action"]),
        target=str(metadata["target"]),
        parameters={"service": metadata["service"]},
        agent_name="remediation_workflow",
        approval_granted=True,
        approval_id=approval_id,
    )
    result = await ExecutionService.execute(request)
    AuditService.record(
        "remediation_executed",
        "remediation_workflow",
        approval["incident_id"],
        approval["action"],
        "success" if result.success else "failed",
        {"approval_id": approval_id, "result": result.model_dump()},
    )
    return result.model_dump()
