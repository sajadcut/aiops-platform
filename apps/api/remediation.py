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
from apps.security.auth import require_permission
from database import AsyncSessionLocal
from domain.models import Finding, Incident

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
    action: str = Field(default="restart_service", pattern="^(restart_service|reload_service|start_service)$")
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

        approval_id = str(uuid4())
        metadata = bind_metadata(
            {
                "service": payload.service, "target_port": payload.target_port,
                "dry_run": payload.dry_run, "reason": payload.reason,
                "finding": finding.statement if finding else None,
            },
            incident_id=str(incident_id), tool_name="ssh_vm", action=payload.action,
            target=payload.target, parameters={"service": payload.service}, timeout=30,
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
        try:
            assert_bound(
                approval, incident_id=incident_id, tool_name="ssh_vm", action=action,
                target=target, parameters={"service": service}, timeout=30,
            )
        except (TypeError, ValueError) as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc

        if bool(metadata.get("dry_run")):
            result = {
                "success": True, "execution_blocked": True, "reason": "dry_run",
                "tool_name": "ssh_vm", "action": action, "target": target, "approval_id": approval_id,
            }
            await _audit_durable(db, "remediation_dry_run", identity.subject, incident_id, action, "simulated", {"approval_id": approval_id})
            return result

        # Fixed precondition: if this service has a configuration validator,
        # a known-invalid configuration blocks start/restart/reload before approval is consumed.
        config_check = await _read_vm("config_validate", target, {"service": service})
        config_result = config_check.result or {}
        if not config_check.success:
            await _audit_durable(db, "remediation_precondition_failed", identity.subject, incident_id, action, "blocked", {
                "approval_id": approval_id, "precondition": "config_validate", "reason": config_check.error,
            })
            raise HTTPException(status_code=409, detail="config_validation_unavailable")
        if config_result.get("supported") is True and config_result.get("valid") is not True:
            await _audit_durable(db, "remediation_precondition_failed", identity.subject, incident_id, action, "blocked", {
                "approval_id": approval_id, "precondition": "config_valid", "config": config_result,
            })
            raise HTTPException(status_code=409, detail="service_configuration_invalid")

        consumed = await store.consume(approval_id)
        if not consumed or consumed.get("status") != "consumed":
            raise HTTPException(status_code=409, detail="approval_already_consumed_or_unavailable")
        await _audit_durable(db, "approval_consumed", identity.subject, incident_id, action, "recorded", {
            "approval_id": approval_id, "tool_name": "ssh_vm", "target": target,
        })

        request = ExecutionRequest(
            tool_name="ssh_vm", action=action, target=target, parameters={"service": service}, timeout=30,
            agent_name="remediation_workflow", incident_id=incident_id, approval_granted=True,
            approval_id=approval_id,
        )
        result = await ExecutionService.execute(request)
        await _audit_durable(db, "remediation_executed", identity.subject, incident_id, action,
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
        service = str(metadata.get("service") or "")
        target_port = metadata.get("target_port")
        if not target or not service:
            raise HTTPException(status_code=409, detail="approval_binding_incomplete")
        if payload.target and payload.target != target:
            raise HTTPException(status_code=409, detail="verification_target_mismatch")

        metrics_execution = await _read_vm("collect_vm_metrics", target, {})
        metrics = (metrics_execution.result or {}).get("metrics", {}) if metrics_execution.success else {}
        cpu = metrics.get("cpu_usage")
        service_execution = await _read_vm("service_status", target, {"service": service})
        service_result = service_execution.result or {}
        service_active = bool(service_execution.success and str(service_result.get("active_state") or service_result.get("status") or "").lower() == "active")

        listener_result: Dict[str, Any] | None = None
        tcp_result: Dict[str, Any] | None = None
        if target_port is not None:
            listener_execution = await _read_vm("port_listener_status", target, {"port": int(target_port)})
            tcp_execution = await _read_vm("tcp_check", target, {"host": target, "port": int(target_port)})
            listener_result = listener_execution.result or {}
            tcp_result = tcp_execution.result or {}
            symptom_recovered = bool(
                listener_execution.success and listener_result.get("listening") is True
                and tcp_execution.success and tcp_result.get("reachable") is True
            )
        else:
            symptom_recovered = bool(metrics_execution.success and isinstance(cpu, (int, float)) and float(cpu) <= payload.cpu_threshold)

        success = bool(service_active and symptom_recovered)
        status = "verified" if success else "not_recovered"
        verification = {
            "approval_id": approval_id, "status": status, "target": target, "service": service,
            "target_port": target_port, "service_active": service_active,
            "port_listening": listener_result.get("listening") if listener_result is not None else None,
            "tcp_reachable": tcp_result.get("reachable") if tcp_result is not None else None,
            "cpu_usage": cpu, "cpu_threshold": payload.cpu_threshold, "metrics": metrics,
            "service_status": service_result, "listener_status": listener_result, "tcp_check": tcp_result,
        }
        await _audit_durable(db, "verification_completed", identity.subject, str(approval["incident_id"]), str(approval["action"]), status, verification)
        return verification
