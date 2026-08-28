from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import desc, select

from apps.approval_service.binding import assert_bound, bind_metadata
from apps.approval_service.postgres import PostgreSQLApprovalStore
from apps.audit_service import AuditService
from apps.audit_service.postgres import PostgreSQLAuditStore
from apps.execution_service import ExecutionRequest, ExecutionService
from apps.execution_service.capability import ExecutionCapabilityError, issue_execution_capability
from apps.security.auth import require_permission
from database import AsyncSessionLocal
from domain.models import Finding, Incident

router = APIRouter()


async def _audit_durable(db, event_type: str, actor: str, incident_id: str, action: str, status: str, metadata: Dict[str, Any]) -> None:
    AuditService.record(event_type, actor, incident_id, action, status, metadata)
    await AuditService.flush_to_store(PostgreSQLAuditStore(db), incident_id=incident_id)
    await db.commit()


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
    identity=Depends(require_permission("approve:low_risk")),
):
    async with AsyncSessionLocal() as db:
        incident = await db.get(Incident, incident_id)
        if incident is None:
            raise HTTPException(status_code=404, detail="incident_not_found")
        finding = (
            await db.execute(select(Finding).where(Finding.incident_id == incident_id).order_by(desc(Finding.created_at)).limit(1))
        ).scalars().first()

        approval_id = str(uuid4())
        metadata = bind_metadata(
            {"service": payload.service, "dry_run": payload.dry_run, "reason": payload.reason, "finding": finding.statement if finding else None},
            incident_id=str(incident_id), tool_name="ssh_vm", action=payload.action, target=payload.target,
            parameters={"service": payload.service}, timeout=30,
        )
        record = {
            "approval_id": approval_id, "incident_id": str(incident_id), "action": payload.action, "risk_level": "high",
            "approver": "SRE-OnCall", "status": "pending", "metadata": metadata,
            "created_at": datetime.now(timezone.utc).isoformat(), "approved_at": None, "rejected_at": None,
        }
        saved = await PostgreSQLApprovalStore(db).save(record)
        await _audit_durable(db, "remediation_requested", identity.subject, str(incident_id), payload.action, "pending_approval", {
            "approval_id": approval_id, "target": payload.target, "service": payload.service, "dry_run": payload.dry_run,
        })
        return saved


@router.post("/approvals/{approval_id}/execute")
async def execute_approved_remediation(approval_id: str, identity=Depends(require_permission("execute:approved"))):
    async with AsyncSessionLocal() as db:
        store = PostgreSQLApprovalStore(db)
        approval = await store.get(approval_id)
        if approval is None:
            raise HTTPException(status_code=404, detail="approval_not_found")

        metadata: Dict[str, Any] = dict(approval.get("metadata") or {})
        service = str(metadata.get("service") or "")
        target = str(metadata.get("target") or "")
        incident_id = str(approval.get("incident_id") or "")
        if not service or not target or not incident_id:
            raise HTTPException(status_code=409, detail="approval_binding_incomplete")
        try:
            assert_bound(
                approval, incident_id=incident_id, tool_name="ssh_vm", action=approval.get("action"), target=target,
                parameters={"service": service}, timeout=30,
            )
        except (TypeError, ValueError) as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc

        if bool(metadata.get("dry_run")):
            result = {
                "success": True, "execution_blocked": True, "reason": "dry_run", "tool_name": "ssh_vm",
                "action": approval["action"], "target": target, "approval_id": approval_id,
            }
            await _audit_durable(db, "remediation_dry_run", identity.subject, incident_id, str(approval["action"]), "simulated", {"approval_id": approval_id})
            return result

        consumed = await store.consume(approval_id)
        if not consumed or consumed.get("status") != "consumed":
            raise HTTPException(status_code=409, detail="approval_already_consumed_or_unavailable")
        try:
            capability = issue_execution_capability(
                incident_id=incident_id, approval_id=approval_id, tool_name="ssh_vm",
                action=str(approval["action"]), target=target, parameters={"service": service}, timeout=30,
            )
        except ExecutionCapabilityError as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from exc
        await _audit_durable(db, "approval_consumed", identity.subject, incident_id, str(approval["action"]), "recorded", {
            "approval_id": approval_id, "tool_name": "ssh_vm", "target": target,
        })

        request = ExecutionRequest(
            tool_name="ssh_vm", action=str(approval["action"]), target=target, parameters={"service": service}, timeout=30,
            agent_name="remediation_workflow", incident_id=incident_id, approval_granted=True, approval_id=approval_id,
            execution_capability=capability,
        )
        result = await ExecutionService.execute(request)
        await _audit_durable(db, "remediation_executed", identity.subject, incident_id, str(approval["action"]),
            "success" if result.success else "failed", {"approval_id": approval_id, "result": result.model_dump()})
        return result.model_dump()


class VMVerificationRequest(BaseModel):
    target: str | None = Field(default=None, min_length=1)
    cpu_threshold: float = Field(default=70.0, ge=1.0, le=100.0)


@router.post("/approvals/{approval_id}/verify")
async def verify_remediation(
    approval_id: str,
    payload: VMVerificationRequest,
    identity=Depends(require_permission("read:incident")),
):
    async with AsyncSessionLocal() as db:
        approval = await PostgreSQLApprovalStore(db).get(approval_id)
        if approval is None:
            raise HTTPException(status_code=404, detail="approval_not_found")
        metadata: Dict[str, Any] = dict(approval.get("metadata") or {})
        expected_status = "approved" if bool(metadata.get("dry_run")) else "consumed"
        if str(approval.get("status")) != expected_status:
            raise HTTPException(status_code=409, detail="approval_not_executed")
        target = str(metadata.get("target") or "")
        if not target:
            raise HTTPException(status_code=409, detail="approval_binding_incomplete")
        if payload.target and payload.target != target:
            raise HTTPException(status_code=409, detail="verification_target_mismatch")

        request = ExecutionRequest(tool_name="vm_telemetry", action="collect_vm_metrics", target=target, parameters={}, agent_name="verification")
        result = await ExecutionService.execute(request)
        metrics = (result.result or {}).get("metrics", {}) if result.success else {}
        cpu = metrics.get("cpu_usage")
        success = bool(result.success and isinstance(cpu, (int, float)) and float(cpu) <= payload.cpu_threshold)
        status = "verified" if success else "not_recovered"

        await _audit_durable(db, "verification_completed", identity.subject, str(approval["incident_id"]), str(approval["action"]), status, {
            "approval_id": approval_id, "metrics": metrics, "cpu_threshold": payload.cpu_threshold, "target": target,
        })
        return {
            "approval_id": approval_id, "status": status, "cpu_usage": cpu, "cpu_threshold": payload.cpu_threshold,
            "metrics": metrics, "execution": result.model_dump(),
        }
