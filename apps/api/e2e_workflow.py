from __future__ import annotations

from typing import Any, Dict, List, Optional
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from apps.orchestrator.runtime import DurableWorkflowRuntime
from apps.security.auth import require_permission
from apps.security.rbac import allowed
from database import AsyncSessionLocal

router = APIRouter()


class ExecutionRequestModel(BaseModel):
    tool_name: str
    action: str
    target: str
    parameters: Dict[str, Any] = Field(default_factory=dict)
    timeout: int = 30


class E2EWorkflowRequest(BaseModel):
    incident_id: Optional[str] = None
    evidence_summary: str = "Application error spike detected"
    service_name: Optional[str] = None
    context: Dict[str, Any] = Field(default_factory=dict)
    execution_request: Optional[ExecutionRequestModel] = None
    before_context: Dict[str, Any] = Field(default_factory=dict)
    after_context: Dict[str, Any] = Field(default_factory=dict)


class E2EWorkflowResponse(BaseModel):
    success: bool
    current_node: Optional[str] = None
    decision: Optional[Dict[str, Any]] = None
    approval: Optional[Dict[str, Any]] = None
    execution_result: Optional[Dict[str, Any]] = None
    verification_result: Optional[Dict[str, Any]] = None
    final_plan: Optional[str] = None
    findings: List[Dict[str, Any]] = Field(default_factory=list)
    messages: List[str] = Field(default_factory=list)
    terminal_reason: Optional[str] = None


def _response_from_result(result: Dict[str, Any]) -> E2EWorkflowResponse:
    return E2EWorkflowResponse(
        success=True,
        current_node=result.get("current_node"),
        decision=result.get("decision"),
        approval=result.get("approval"),
        execution_result=result.get("execution_result"),
        verification_result=result.get("verification_result"),
        final_plan=result.get("final_plan"),
        findings=result.get("findings", []),
        messages=result.get("messages", []),
        terminal_reason=result.get("terminal_reason"),
    )


@router.post("/workflow/e2e", response_model=E2EWorkflowResponse)
async def run_e2e_workflow(
    request: E2EWorkflowRequest,
    identity=Depends(require_permission("read:incident")),
) -> E2EWorkflowResponse:
    """Run the guarded durable incident lifecycle without bypassing Decision/Approval."""
    try:
        if request.execution_request is not None and not any(
            allowed(role, "execute:low_risk") or allowed(role, "execute:approved")
            for role in identity.roles
        ):
            raise HTTPException(status_code=403, detail="execution_permission_required")

        incident_id = request.incident_id or str(uuid4())
        initial_state: Dict[str, Any] = {
            "incident_id": incident_id,
            "evidence_summary": request.evidence_summary,
            "service_name": request.service_name,
            "context": request.context,
            "before_context": request.before_context,
            "after_context": request.after_context,
            "messages": [],
            "findings": [],
            "confidence": 0.0,
        }
        if request.execution_request is not None:
            initial_state["execution_request"] = request.execution_request.model_dump()

        async with AsyncSessionLocal() as db:
            result = await DurableWorkflowRuntime(db).start(initial_state)

        return _response_from_result(result)
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.post("/workflow/e2e/{incident_id}/resume", response_model=E2EWorkflowResponse)
async def resume_e2e_workflow(
    incident_id: str,
    _identity=Depends(require_permission("execute:approved")),
) -> E2EWorkflowResponse:
    """Resume a paused workflow only after its durable approval is granted."""
    try:
        async with AsyncSessionLocal() as db:
            result = await DurableWorkflowRuntime(db).resume_after_approval(incident_id)
        return _response_from_result(result)
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc
