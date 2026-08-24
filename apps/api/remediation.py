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
    action: str = Field(default="restart_service", pattern="^restart_service$")
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
        {"approval_id": approval_id, "target": payload.target, "service": payload.service, "dry_run": payload.dry_run},
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
    if bool(metadata.get("dry_run")):
        result = {
            "success": True,
            "execution_blocked": True,
            "reason": "dry_run",
            "tool_name": "ssh_vm",
            "action": approval["action"],
            "target": metadata.get("target"),
            "approval_id": approval_id,
        }
        AuditService.record("remediation_dry_run", "remediation_workflow", approval["incident_id"], approval["action"], "simulated", {"approval_id": approval_id})
        return result

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


class VMVerificationRequest(BaseModel):
    target: str = Field(min_length=1)
    cpu_threshold: float = Field(default=70.0, ge=1.0, le=100.0)


@router.post("/approvals/{approval_id}/verify")
async def verify_remediation(
    approval_id: str,
    payload: VMVerificationRequest,
    _user=Depends(require_permission("read:incident")),
):
    async with AsyncSessionLocal() as db:
        approval = await PostgreSQLApprovalStore(db).get(approval_id)
    if approval is None:
        raise HTTPException(status_code=404, detail="Approval not found")
    if approval.get("status") != "approved":
        raise HTTPException(status_code=409, detail="Approval is not approved")

    request = ExecutionRequest(
        tool_name="vm_telemetry",
        action="collect_vm_metrics",
        target=payload.target,
        parameters={},
        agent_name="verification",
        approval_granted=True,
    )
    result = await ExecutionService.execute(request)
    metrics = (result.result or {}).get("metrics", {}) if result.success else {}
    cpu = metrics.get("cpu_usage")
    success = bool(result.success and isinstance(cpu, (int, float)) and float(cpu) <= payload.cpu_threshold)
    status = "verified" if success else "not_recovered"

    AuditService.record(
        "verification_completed",
        "verification",
        approval["incident_id"],
        approval["action"],
        status,
        {"approval_id": approval_id, "metrics": metrics, "cpu_threshold": payload.cpu_threshold},
    )
    return {
        "approval_id": approval_id,
        "status": status,
        "cpu_usage": cpu,
        "cpu_threshold": payload.cpu_threshold,
        "metrics": metrics,
        "execution": result.model_dump(),
    }
