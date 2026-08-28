from __future__ import annotations

from typing import Any, Dict
from uuid import UUID, uuid4
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from apps.approval_service.postgres import PostgreSQLApprovalStore
from apps.audit_service import AuditService
from apps.audit_service.postgres import PostgreSQLAuditStore
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


async def _audit_durable(
    db,
    event_type: str,
    actor: str,
    incident_id: str | None,
    action: str | None,
    status: str,
    metadata: Dict[str, Any],
) -> None:
    AuditService.record(event_type, actor, incident_id, action, status, metadata)
    await AuditService.flush_to_store(PostgreSQLAuditStore(db), incident_id=incident_id)


@router.post("/incidents/{incident_id}/remediation-requests")
async def create_remediation_request(
    incident_id: UUID,
    payload: RemediationRequest,
    identity=Depends(require_permission("approve:low_risk")),
):
    async with AsyncSessionLocal() as db:
        incident = await db.get(Incident, incident_id)
        if incident is None:
            raise HTTPException(status_code=404, detail="Incident not found")
        finding = (await db.execute(
            select(Finding).where(Finding.incident_id == incident_id).order_by(desc(Finding.created_at)).limit(1)
        )).scalars().first()

        approval_id = str(uuid4())
        parameters = {"service": payload.service}
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
                "parameters": parameters,
                "dry_run": payload.dry_run,
                "reason": payload.reason,
                "finding": finding.statement if finding else None,
                "binding_complete": True,
            },
            "created_at": datetime.now(timezone.utc).isoformat(),
            "approved_at": None,
            "rejected_at": None,
        }
        saved = await PostgreSQLApprovalStore(db).save(record)
        await _audit_durable(
            db,
            "remediation_requested",
            identity.subject,
            str(incident_id),
            payload.action,
            "pending_approval",
            {
                "approval_id": approval_id,
                "target": payload.target,
                "parameters": parameters,
                "dry_run": payload.dry_run,
            },
        )
        return saved


@router.post("/approvals/{approval_id}/execute")
async def execute_approved_remediation(
    approval_id: str,
    identity=Depends(require_permission("execute:approved")),
):
    async with AsyncSessionLocal() as db:
        store = PostgreSQLApprovalStore(db)
        approval = await store.get(approval_id)
        if approval is None:
            raise HTTPException(status_code=404, detail="Approval not found")
        if approval.get("status") != "approved":
            raise HTTPException(status_code=409, detail="Approval is not approved")

        metadata: Dict[str, Any] = approval.get("metadata") or {}
        target = str(metadata.get("target") or "").strip()
        service = str(metadata.get("service") or "").strip()
        tool_name = str(metadata.get("tool_name") or "").strip()
        if not target or not service or tool_name != "ssh_vm":
            raise HTTPException(status_code=409, detail="Approval remediation binding is incomplete")

        if bool(metadata.get("dry_run")):
            result = {
                "success": True,
                "execution_blocked": True,
                "reason": "dry_run",
                "tool_name": tool_name,
                "action": approval["action"],
                "target": target,
                "approval_id": approval_id,
            }
            await _audit_durable(
                db,
                "remediation_dry_run",
                identity.subject,
                str(approval["incident_id"]),
                str(approval["action"]),
                "simulated",
                {"approval_id": approval_id, "target": target, "service": service},
            )
            return result

        consumed = await store.consume(approval_id)
        if not consumed or consumed.get("status") != "consumed":
            raise HTTPException(status_code=409, detail="Approval already consumed or unavailable")
        await _audit_durable(
            db,
            "approval_consumed",
            identity.subject,
            str(approval["incident_id"]),
            str(approval["action"]),
            "recorded",
            {"approval_id": approval_id, "tool_name": tool_name, "target": target, "service": service},
        )

        request = ExecutionRequest(
            tool_name=tool_name,
            action=str(approval["action"]),
            target=target,
            parameters={"service": service},
            agent_name="remediation_workflow",
            approval_granted=True,
            approval_id=approval_id,
        )
        result = await ExecutionService.execute(request)
        await _audit_durable(
            db,
            "remediation_executed",
            identity.subject,
            str(approval["incident_id"]),
            str(approval["action"]),
            "success" if result.success else "failed",
            {"approval_id": approval_id, "result": result.model_dump()},
        )
        return result.model_dump()


class VMVerificationRequest(BaseModel):
    # Kept optional for backward API compatibility. If supplied it must match
    # the target persisted in the approval binding.
    target: str | None = None


@router.post("/approvals/{approval_id}/verify")
async def verify_remediation(
    approval_id: str,
    payload: VMVerificationRequest,
    identity=Depends(require_permission("read:incident")),
):
    async with AsyncSessionLocal() as db:
        approval = await PostgreSQLApprovalStore(db).get(approval_id)
        if approval is None:
            raise HTTPException(status_code=404, detail="Approval not found")
        if approval.get("status") != "consumed":
            raise HTTPException(status_code=409, detail="Approval has not been consumed by an execution")

        metadata: Dict[str, Any] = approval.get("metadata") or {}
        target = str(metadata.get("target") or "").strip()
        service = str(metadata.get("service") or "").strip()
        if not target or not service:
            raise HTTPException(status_code=409, detail="Approval remediation binding is incomplete")
        if payload.target is not None and str(payload.target) != target:
            raise HTTPException(status_code=409, detail="Verification target does not match approved target")

        request = ExecutionRequest(
            tool_name="vm_telemetry",
            action="service_status",
            target=target,
            parameters={"service": service},
            agent_name="verification",
            approval_granted=False,
        )
        result = await ExecutionService.execute(request)
        service_status = (result.result or {}).get("status", {}) if result.success else {}
        active_state = str(service_status.get("ActiveState") or "unknown")
        sub_state = str(service_status.get("SubState") or "unknown")
        success = bool(result.success and active_state == "active")
        status = "verified" if success else "not_recovered"

        await _audit_durable(
            db,
            "verification_completed",
            identity.subject,
            str(approval["incident_id"]),
            str(approval["action"]),
            status,
            {
                "approval_id": approval_id,
                "target": target,
                "service": service,
                "active_state": active_state,
                "sub_state": sub_state,
                "execution": result.model_dump(),
            },
        )
        return {
            "approval_id": approval_id,
            "status": status,
            "target": target,
            "service": service,
            "active_state": active_state,
            "sub_state": sub_state,
            "execution": result.model_dump(),
        }
