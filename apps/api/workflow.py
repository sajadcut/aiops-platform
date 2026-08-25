from __future__ import annotations

from typing import Any, Dict, List, Optional
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from apps.orchestrator.runtime import DurableWorkflowRuntime
from apps.security.auth import require_permission
from database import AsyncSessionLocal
from domain.contracts.logging import logger

router = APIRouter()


class WorkflowRequest(BaseModel):
    evidence_summary: str = "Application error spike detected after recent deployment"
    incident_id: Optional[str] = None
    service_name: Optional[str] = None
    context: Dict[str, Any] = Field(default_factory=dict)


class WorkflowResponse(BaseModel):
    success: bool
    incident_id: str
    triage_result: Optional[Dict[str, Any]] = None
    analysis_results: Optional[List[Dict[str, Any]]] = None
    final_plan: Optional[str] = None
    evaluation: Optional[Dict[str, Any]] = None
    decision: Optional[Dict[str, Any]] = None
    terminal_reason: Optional[str] = None
    messages: List[str] = Field(default_factory=list)
    findings: List[Dict[str, Any]] = Field(default_factory=list)


@router.post("/workflow/analyze", response_model=WorkflowResponse)
async def run_workflow(
    request: WorkflowRequest,
    _identity=Depends(require_permission("read:incident")),
):
    """Compatibility analysis endpoint backed by the canonical durable E2E runtime."""
    incident_id = request.incident_id or str(uuid4())
    try:
        initial_state: Dict[str, Any] = {
            "incident_id": incident_id,
            "evidence_summary": request.evidence_summary,
            "service_name": request.service_name,
            "context": request.context,
            "messages": [],
            "findings": [],
            "confidence": 0.0,
        }
        async with AsyncSessionLocal() as db:
            result = await DurableWorkflowRuntime(db).start(initial_state)
        return WorkflowResponse(
            success=True,
            incident_id=incident_id,
            triage_result=result.get("triage_result"),
            analysis_results=result.get("analysis_results"),
            final_plan=result.get("final_plan"),
            evaluation=result.get("evaluation"),
            decision=result.get("decision"),
            terminal_reason=result.get("terminal_reason"),
            messages=result.get("messages", []),
            findings=result.get("findings", []),
        )
    except Exception as exc:
        logger.error(f"Workflow failed: {exc}")
        raise HTTPException(status_code=500, detail="workflow_failed") from exc
