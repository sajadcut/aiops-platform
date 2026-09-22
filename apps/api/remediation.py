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
from apps.runbook_service.registry import RunbookRegistry
from apps.runbook_service.learning import record_runbook_outcome
from apps.memory_service import OperationalMemoryService
from apps.incident_service.repository import IncidentRepository
from apps.runbook_service.runtime_guard import RunbookRuntimeGuard
from apps.security.auth import require_permission
from database import AsyncSessionLocal
from domain.contracts.logging import logger
from domain.models import Finding, Incident, MemoryEntry

router = APIRouter()


async def _audit_durable(db, event_type: str, actor: str, incident_id: str, action: str, status: str, metadata: Dict[str, Any]) -> None:
    AuditService.record(event_type, actor, incident_id, action, status, metadata)
    await AuditService.flush_to_store(PostgreSQLAuditStore(db), incident_id=incident_id)
    await db.commit()


async def _read_vm(action: str, target: str, parameters: Dict[str, Any]) -> Any:
    return await ExecutionService.execute(ExecutionRequest(
        tool_name="vm_telemetry", action=action, target=target,
        parameters=parameters, agent_name="remediation_precondition",
    ))


class RemediationRequest(BaseModel):
    target: str = Field(min_length=1)
    service: str = Field(min_length=1)
    action: str = Field(default="restart_service", pattern="^(restart_service|start_service)$")
    target_port: int | None = Field(default=None, ge=1, le=65535)
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

        runbook = RunbookRegistry("runbooks").get(
            RunbookRuntimeGuard.VM_SERVICE_RUNBOOK
        )
        runbook_version = str(runbook.get("version") or "")
        approval_id = str(uuid4())
        bound_parameters: Dict[str, Any] = {"service": payload.service}
        if payload.target_port is not None:
            bound_parameters["target_port"] = payload.target_port
        metadata = bind_metadata(
            {
                "service": payload.service,
                "target_port": payload.target_port,
                "dry_run": payload.dry_run,
                "reason": payload.reason,
                "finding": finding.statement if finding else None,
            },
            incident_id=str(incident_id),
            tool_name="ssh_vm",
            action=payload.action,
            target=payload.target,
            parameters=bound_parameters,
            timeout=30,
            runbook_id=RunbookRuntimeGuard.VM_SERVICE_RUNBOOK,
            runbook_version=runbook_version,
        )
        record = {
            "approval_id": approval_id, "incident_id": str(incident_id), "action": payload.action,
            "risk_level": "high", "approver": "SRE-OnCall", "status": "pending",
            "metadata": metadata, "created_at": datetime.now(timezone.utc).isoformat(),
            "approved_at": None, "rejected_at": None,
        }
        saved = await PostgreSQLApprovalStore(db).save(record)
        await _audit_durable(db, "remediation_requested", identity.subject, str(incident_id), payload.action, "pending_approval", {
            "approval_id": approval_id, "target": payload.target, "service": payload.service,
            "target_port": payload.target_port, "dry_run": payload.dry_run,
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
        action = str(approval.get("action") or "")
        if not service or not target or not incident_id:
            raise HTTPException(status_code=409, detail="approval_binding_incomplete")
        target_port = metadata.get("target_port")
        bound_parameters: Dict[str, Any] = {"service": service}
        if target_port is not None:
            bound_parameters["target_port"] = int(target_port)
        runbook_id = str(
            metadata.get("runbook_id")
            or RunbookRuntimeGuard.VM_SERVICE_RUNBOOK
        )
        runbook_version = str(metadata.get("runbook_version") or "")
        try:
            assert_bound(
                approval,
                incident_id=incident_id,
                tool_name="ssh_vm",
                action=action,
                target=target,
                parameters=bound_parameters,
                timeout=30,
                runbook_id=runbook_id,
                runbook_version=runbook_version,
            )
        except (TypeError, ValueError) as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc

        before_snapshot = await RunbookRuntimeGuard.collect_snapshot(
            runbook_id=runbook_id,
            target=target,
            parameters=bound_parameters,
            incident_id=incident_id,
            phase="pre",
        )
        precondition = RunbookRuntimeGuard.preflight(
            runbook_id=runbook_id,
            tool_name="ssh_vm",
            action=action,
            target=target,
            parameters=bound_parameters,
            incident_id=incident_id,
            evidence=list(before_snapshot.get("evidence") or []),
        )
        if not precondition.get("safe_to_execute"):
            await _audit_durable(
                db,
                "remediation_precondition_failed",
                identity.subject,
                incident_id,
                action,
                "blocked",
                {
                    "approval_id": approval_id,
                    "precondition": precondition,
                    "snapshot_error": before_snapshot.get("error"),
                },
            )
            raise HTTPException(
                status_code=409,
                detail=(
                    "remediation_precondition_failed:"
                    + str(
                        precondition.get("reason")
                        or "runtime_precondition_failed"
                    )
                ),
            )

        if bool(metadata.get("dry_run")):
            result = {
                "success": True,
                "execution_blocked": True,
                "reason": "dry_run",
                "tool_name": "ssh_vm",
                "action": action,
                "target": target,
                "approval_id": approval_id,
                "precondition": precondition,
            }
            await _audit_durable(
                db,
                "remediation_dry_run",
                identity.subject,
                incident_id,
                action,
                "simulated",
                {"approval_id": approval_id, "precondition": precondition},
            )
            return result

        consumed = await store.consume(approval_id)
        if not consumed or consumed.get("status") != "consumed":
            raise HTTPException(status_code=409, detail="approval_already_consumed_or_unavailable")
        await _audit_durable(db, "approval_consumed", identity.subject, incident_id, action, "recorded", {
            "approval_id": approval_id, "tool_name": "ssh_vm", "target": target,
        })

        runbook = RunbookRegistry("runbooks").get(runbook_id)
        after_snapshot = None

        request = ExecutionRequest(
            tool_name="ssh_vm",
            action=action,
            target=target,
            parameters=bound_parameters,
            timeout=30,
            agent_name="remediation_workflow",
            incident_id=incident_id,
            approval_granted=True,
            approval_id=approval_id,
            runbook_id=runbook_id,
            runbook_version=runbook_version,
        )
        result = await ExecutionService.execute(request)
        response = result.model_dump()
        verification_payload = None
        verified = False

        if result.success:
            after_snapshot = await RunbookRuntimeGuard.collect_snapshot(
                runbook_id=runbook_id,
                target=target,
                parameters=bound_parameters,
                incident_id=incident_id,
                phase="post",
            )
            verification = await RunbookRuntimeGuard.verify(
                runbook=runbook,
                action=action,
                service=service,
                before_context=dict(
                    (before_snapshot or {}).get("context") or {}
                ),
                after_context=dict(after_snapshot.get("context") or {}),
            )
            verification_payload = verification.model_dump(mode="json")
            verification_payload["snapshot_error"] = after_snapshot.get("error")
            verified = (
                verification.status.value == "success"
                and verification.required_objectives_met is True
            )
        else:
            verification_payload = {
                "status": "failed",
                "verification_policy": "execution_failed_before_verification",
                "required_objectives_met": False,
                "message": (
                    result.error
                    or result.reason
                    or "Remediation execution failed before verification."
                ),
            }

        response["precondition"] = precondition
        response["verification"] = verification_payload
        response["verified"] = verified

        memory_id = None
        memory_error = None
        try:
            memory_id = await record_runbook_outcome(
                db,
                incident_id=incident_id,
                runbook=runbook,
                tool_name=request.tool_name,
                action=request.action,
                target=request.target,
                parameters=dict(request.parameters or {}),
                approval=consumed,
                execution_result=result.model_dump(mode="json"),
                verification_result=dict(verification_payload or {}),
                before_snapshot=before_snapshot,
                after_snapshot=after_snapshot,
            )
            if memory_id:
                response["operational_memory_writeback"] = {
                    "memory_id": memory_id,
                    "verification_status": (
                        verification_payload or {}
                    ).get("status"),
                }
        except Exception as exc:
            memory_error = type(exc).__name__
            logger.error(
                "remediation_operational_memory_writeback_failed",
                incident_id=incident_id,
                action=action,
                error_type=memory_error,
            )

        incidents = IncidentRepository(db)
        incident_status = await incidents.record_operational_outcome(
            incident_id,
            source="remediation_execution",
            action=action,
            target=target,
            approval_id=approval_id,
            execution_success=bool(result.success),
            verified=bool(verified),
            verification=dict(verification_payload or {}),
            memory_id=memory_id,
        )
        await incidents.commit()
        response["incident_status"] = incident_status

        await _audit_durable(
            db,
            "remediation_executed",
            identity.subject,
            incident_id,
            action,
            "verified" if verified else "failed",
            {
                "approval_id": approval_id,
                "result": result.model_dump(),
                "precondition": precondition,
                "verification": verification_payload,
                "verified": verified,
                "memory_id": memory_id,
                "memory_error": memory_error,
                "incident_status": incident_status,
            },
        )
        return response


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
        if bool(metadata.get("dry_run")):
            raise HTTPException(
                status_code=409,
                detail="dry_run_has_no_executed_recovery_to_verify",
            )
        if str(approval.get("status") or "") != "consumed":
            raise HTTPException(status_code=409, detail="approval_not_executed")

        target = str(metadata.get("target") or "")
        service = str(metadata.get("service") or "")
        incident_id = str(approval.get("incident_id") or "")
        action = str(approval.get("action") or "")
        target_port = metadata.get("target_port")
        runbook_id = str(
            metadata.get("runbook_id")
            or RunbookRuntimeGuard.VM_SERVICE_RUNBOOK
        )
        if not target or not service or not incident_id or not action:
            raise HTTPException(status_code=409, detail="approval_binding_incomplete")
        if payload.target and payload.target != target:
            raise HTTPException(status_code=409, detail="verification_target_mismatch")

        bound_parameters: Dict[str, Any] = {"service": service}
        if target_port is not None:
            bound_parameters["target_port"] = int(target_port)

        runbook = RunbookRegistry("runbooks").get(runbook_id)
        snapshot = await RunbookRuntimeGuard.collect_snapshot(
            runbook_id=runbook_id,
            target=target,
            parameters=bound_parameters,
            incident_id=incident_id,
            phase="manual_verify",
        )
        verification_result = await RunbookRuntimeGuard.verify(
            runbook=runbook,
            action=action,
            service=service,
            before_context={},
            after_context=dict(snapshot.get("context") or {}),
        )
        verification = verification_result.model_dump(mode="json")
        verified = (
            verification_result.status.value == "success"
            and verification_result.required_objectives_met is True
        )

        memory_id = None
        memory_validated = False
        historical_execution_success = None
        try:
            incident_uuid = UUID(incident_id)
        except ValueError:
            incident_uuid = None
        if incident_uuid is not None:
            rows = (
                await db.execute(
                    select(MemoryEntry)
                    .where(MemoryEntry.incident_id == incident_uuid)
                    .order_by(desc(MemoryEntry.created_at))
                    .limit(20)
                )
            ).scalars().all()
            for row in rows:
                remediation = (
                    row.actual_remediation
                    if isinstance(row.actual_remediation, dict)
                    else {}
                )
                if str(remediation.get("approval_id") or "") != approval_id:
                    continue
                memory_id = str(row.id)
                if "execution_success" in remediation:
                    historical_execution_success = bool(
                        remediation.get("execution_success")
                    )
                if verified:
                    memory_validated = await OperationalMemoryService(
                        db
                    ).mark_validated(row.id)
                break

        incidents = IncidentRepository(db)
        incident_status = await incidents.record_operational_outcome(
            incident_id,
            source="manual_verification",
            action=action,
            target=target,
            approval_id=approval_id,
            execution_success=historical_execution_success,
            verified=bool(verified),
            verification=verification,
            memory_id=memory_id,
        )
        await incidents.commit()

        response = {
            "approval_id": approval_id,
            "status": "verified" if verified else "not_recovered",
            "verification_status": verification_result.status.value,
            "verified": verified,
            "target": target,
            "service": service,
            "target_port": target_port,
            "runbook_id": runbook_id,
            "verification": verification,
            "snapshot_error": snapshot.get("error"),
            "memory_id": memory_id,
            "memory_validated": memory_validated,
            "incident_status": incident_status,
        }
        await _audit_durable(
            db,
            "verification_completed",
            identity.subject,
            incident_id,
            action,
            "verified" if verified else verification_result.status.value,
            response,
        )
        return response

