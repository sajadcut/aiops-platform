# ============================================================
# FILE: app/api/execution.py
# ============================================================

from typing import Any, Dict

from fastapi import APIRouter, HTTPException

from app.services.approval_service import (
    ApprovalService,
)

from app.services.execution_service import (
    ExecutionService,
    ExecutionRequest,
)


router = APIRouter()


@router.post("/approvals")
async def create_approval(
    payload: Dict[str, Any],
):

    required = [
        "incident_id",
        "action",
        "risk_level",
        "approver",
    ]

    missing = [
        field
        for field in required
        if field not in payload
    ]

    if missing:
        raise HTTPException(
            status_code=400,
            detail={
                "message": "Missing required fields",
                "fields": missing,
            },
        )

    return ApprovalService.create_request(
        incident_id=str(
            payload["incident_id"]
        ),
        action=str(
            payload["action"]
        ),
        risk_level=str(
            payload["risk_level"]
        ),
        approver=str(
            payload["approver"]
        ),
    )


@router.get(
    "/approvals/{approval_id}"
)
async def get_approval(
    approval_id: str,
):

    approval = ApprovalService.get(
        approval_id
    )

    if approval is None:
        raise HTTPException(
            status_code=404,
            detail="Approval not found",
        )

    return approval


@router.post(
    "/approvals/{approval_id}/approve"
)
async def approve(
    approval_id: str,
):

    approval = ApprovalService.approve(
        approval_id
    )

    if approval is None:
        raise HTTPException(
            status_code=404,
            detail="Approval not found",
        )

    return approval


@router.post(
    "/approvals/{approval_id}/reject"
)
async def reject(
    approval_id: str,
):

    approval = ApprovalService.reject(
        approval_id
    )

    if approval is None:
        raise HTTPException(
            status_code=404,
            detail="Approval not found",
        )

    return approval


@router.post("/execute")
async def execute(
    payload: Dict[str, Any],
):

    try:
        request = ExecutionRequest(
            tool_name=payload["tool_name"],
            action=payload["action"],
            target=payload["target"],
            parameters=payload.get(
                "parameters",
                {},
            ),
            timeout=payload.get(
                "timeout",
                30,
            ),
            agent_name=payload.get(
                "agent_name",
                "api",
            ),
            approval_granted=False,
            approval_id=payload.get(
                "approval_id"
            ),
        )

    except Exception as exc:
        raise HTTPException(
            status_code=400,
            detail=str(exc),
        )

    if request.approval_id:

        approval = ApprovalService.get(
            request.approval_id
        )

        if approval is None:
            raise HTTPException(
                status_code=404,
                detail="Approval not found",
            )

        request.approval_granted = (
            approval["status"] == "approved"
        )

    result = await ExecutionService.execute(
        request
    )

    return result.model_dump()