from typing import Any, Dict

from fastapi import APIRouter, Depends, HTTPException

from apps.approval_service import ApprovalService
from apps.execution_service import ExecutionRequest, ExecutionService
from apps.security.auth import require_permission

router = APIRouter()


@router.post("/approvals")
async def create_approval(payload: Dict[str, Any], _user=Depends(require_permission("approve:low_risk"))):
    required_fields = ["incident_id", "action", "risk_level", "approver"]
    missing = [field for field in required_fields if field not in payload]
    if missing:
        raise HTTPException(status_code=400, detail={"code": "MISSING_FIELDS", "fields": missing})
    return ApprovalService.create_request(
        incident_id=str(payload["incident_id"]),
        action=str(payload["action"]),
        risk_level=str(payload["risk_level"]),
        approver=str(payload["approver"]),
        metadata=payload.get("metadata", {}),
    )


@router.get("/approvals/{approval_id}")
async def get_approval(approval_id: str, _user=Depends(require_permission("read:incident"))):
    approval = ApprovalService.get(approval_id)
    if approval is None:
        raise HTTPException(status_code=404, detail="Approval not found")
    return approval


@router.post("/approvals/{approval_id}/approve")
async def approve(approval_id: str, _user=Depends(require_permission("approve:low_risk"))):
    approval = ApprovalService.approve(approval_id)
    if approval is None:
        raise HTTPException(status_code=404, detail="Approval not found")
    return approval


@router.post("/approvals/{approval_id}/reject")
async def reject(approval_id: str, _user=Depends(require_permission("approve:low_risk"))):
    approval = ApprovalService.reject(approval_id)
    if approval is None:
        raise HTTPException(status_code=404, detail="Approval not found")
    return approval


@router.post("/execute")
async def execute(payload: Dict[str, Any], _user=Depends(require_permission("execute:approved"))):
    required_fields = ["tool_name", "action", "target"]
    missing = [field for field in required_fields if field not in payload]
    if missing:
        raise HTTPException(status_code=400, detail={"code": "MISSING_FIELDS", "fields": missing})

    approval_id = payload.get("approval_id")
    approval_granted = False
    if approval_id:
        approval = ApprovalService.get(approval_id)
        if approval is None:
            raise HTTPException(status_code=404, detail="Approval not found")
        approval_granted = approval["status"] == "approved"

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
