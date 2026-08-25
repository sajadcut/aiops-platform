from datetime import datetime, timezone
from typing import Any, Dict
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException

from apps.approval_service.postgres import PostgreSQLApprovalStore
from apps.audit_service import AuditService
from apps.execution_service import ExecutionRequest, ExecutionService
from apps.security.auth import require_permission
from database import AsyncSessionLocal

router = APIRouter()


def _approval_record(payload: Dict[str, Any]) -> Dict[str, Any]:
    now = datetime.now(timezone.utc).isoformat()
    metadata = dict(payload.get("metadata", {}))
    if payload.get("target") is not None:
        metadata.setdefault("target", str(payload["target"]))
    if payload.get("tool_name") is not None:
        metadata.setdefault("tool_name", str(payload["tool_name"]))
    return {
        "approval_id": str(uuid4()),
        "incident_id": str(payload["incident_id"]),
        "action": str(payload["action"]),
        "risk_level": str(payload["risk_level"]),
        "approver": str(payload["approver"]),
        "status": "pending",
        "metadata": metadata,
        "created_at": now,
        "approved_at": None,
        "rejected_at": None,
    }


@router.post("/approvals")
async def create_approval(payload: Dict[str, Any], _user=Depends(require_permission("approve:low_risk"))):
    required_fields = ["incident_id", "action", "risk_level", "approver"]
    missing = [field for field in required_fields if field not in payload]
    if missing:
        raise HTTPException(status_code=400, detail={"code": "MISSING_FIELDS", "fields": missing})
    record = _approval_record(payload)
    async with AsyncSessionLocal() as db:
        return await PostgreSQLApprovalStore(db).save(record)


@router.get("/approvals/{approval_id}")
async def get_approval(approval_id: str, _user=Depends(require_permission("read:incident"))):
    async with AsyncSessionLocal() as db:
        approval = await PostgreSQLApprovalStore(db).get(approval_id)
    if approval is None:
        raise HTTPException(status_code=404, detail="Approval not found")
    return approval


@router.post("/approvals/{approval_id}/approve")
async def approve(approval_id: str, _user=Depends(require_permission("approve:low_risk"))):
    async with AsyncSessionLocal() as db:
        approval = await PostgreSQLApprovalStore(db).set_status(approval_id, "approved")
    if approval is None:
        raise HTTPException(status_code=404, detail="Approval not found")
    AuditService.record("approval_granted", "api", approval["incident_id"], approval["action"], "recorded", {"approval_id": approval_id})
    return approval


@router.post("/approvals/{approval_id}/reject")
async def reject(approval_id: str, _user=Depends(require_permission("approve:low_risk"))):
    async with AsyncSessionLocal() as db:
        approval = await PostgreSQLApprovalStore(db).set_status(approval_id, "rejected")
    if approval is None:
        raise HTTPException(status_code=404, detail="Approval not found")
    return approval


def _validate_approval_binding(approval: Dict[str, Any], payload: Dict[str, Any]) -> None:
    if approval.get("status") != "approved":
        raise HTTPException(status_code=409, detail="Approval is not approved")
    incident_id = payload.get("incident_id")
    if incident_id is None:
        raise HTTPException(status_code=400, detail="incident_id is required when approval_id is supplied")
    if str(approval.get("incident_id")) != str(incident_id):
        raise HTTPException(status_code=409, detail="Approval incident does not match execution request")
    if str(approval.get("action")) != str(payload.get("action")):
        raise HTTPException(status_code=409, detail="Approval action does not match execution request")
    metadata = approval.get("metadata") or {}
    approved_target = metadata.get("target")
    if approved_target is not None and str(approved_target) != str(payload.get("target")):
        raise HTTPException(status_code=409, detail="Approval target does not match execution request")
    approved_tool = metadata.get("tool_name")
    if approved_tool is not None and str(approved_tool) != str(payload.get("tool_name")):
        raise HTTPException(status_code=409, detail="Approval tool does not match execution request")


@router.post("/execute")
async def execute(payload: Dict[str, Any], _user=Depends(require_permission("execute:approved"))):
    required_fields = ["tool_name", "action", "target"]
    missing = [field for field in required_fields if field not in payload]
    if missing:
        raise HTTPException(status_code=400, detail={"code": "MISSING_FIELDS", "fields": missing})

    approval_id = payload.get("approval_id")
    approval_granted = False
    if approval_id:
        async with AsyncSessionLocal() as db:
            approval = await PostgreSQLApprovalStore(db).get(str(approval_id))
        if approval is None:
            raise HTTPException(status_code=404, detail="Approval not found")
        _validate_approval_binding(approval, payload)
        approval_granted = True

    request = ExecutionRequest(
        tool_name=str(payload["tool_name"]),
        action=str(payload["action"]),
        target=str(payload["target"]),
        parameters=payload.get("parameters", {}),
        timeout=int(payload.get("timeout", 30)),
        agent_name=str(payload.get("agent_name", "api")),
        approval_granted=approval_granted,
        approval_id=approval_id,
    )
    result = await ExecutionService.execute(request)
    return result.model_dump()
