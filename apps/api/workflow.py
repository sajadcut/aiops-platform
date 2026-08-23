from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from apps.orchestrator.graph import WorkflowOrchestrator
from domain.contracts.logging import logger
from typing import Optional, List, Dict, Any

router = APIRouter()

class WorkflowRequest(BaseModel):
    evidence_summary: str = "Application error spike detected after recent deployment"
    incident_id: Optional[str] = None
    service_name: Optional[str] = None
    context: Optional[Dict[str, Any]] = None

class WorkflowResponse(BaseModel):
    success: bool
    triage_result: Optional[Dict[str, Any]] = None
    analysis_results: Optional[List[Dict[str, Any]]] = None
    final_plan: Optional[str] = None
    messages: List[str]
    findings: List[Dict[str, Any]]

@router.post("/workflow/analyze", response_model=WorkflowResponse)
async def run_workflow(request: WorkflowRequest):
    """
    اجرای کامل workflow با Triage → Parallel Agents → Synthesis
    """
    try:
        logger.info(f"Workflow requested for incident: {request.incident_id}")
        
        orchestrator = WorkflowOrchestrator()
        
        initial_state = {
            "incident_id": request.incident_id,
            "evidence_summary": request.evidence_summary,
            "service_name": request.service_name,
            "context": request.context or {},
            "messages": [],
            "findings": [],
            "confidence": 0.0
        }
        
        result = await orchestrator.run(initial_state)
        
        return WorkflowResponse(
            success=True,
            triage_result=result.get("triage_result"),
            analysis_results=result.get("analysis_results"),
            final_plan=result.get("final_plan"),
            messages=result.get("messages", []),
            findings=result.get("findings", [])
        )
        
    except Exception as e:
        logger.error(f"Workflow failed: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))