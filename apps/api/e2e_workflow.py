from __future__ import annotations

from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from apps.orchestrator.e2e_graph import E2EOrchestrator

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


@router.post("/workflow/e2e", response_model=E2EWorkflowResponse)
async def run_e2e_workflow(request: E2EWorkflowRequest) -> E2EWorkflowResponse:
    """Run the guarded incident lifecycle without bypassing Decision/Approval."""
    try:
        initial_state: Dict[str, Any] = {
            "incident_id": request.incident_id,
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

        result = await E2EOrchestrator().run(initial_state)
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
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc
