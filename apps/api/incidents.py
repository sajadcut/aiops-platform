from fastapi import APIRouter, HTTPException, Depends, Request
from domain.schemas import IncidentCreate
from domain.contracts.logging import logger
from domain.contracts.rate_limit import rate_limiter_default, rate_limiter_strict
from domain.contracts.context import get_trace_id
from database import AsyncSessionLocal
from uuid import uuid4

router = APIRouter()


@router.post("/incidents/simulate", dependencies=[Depends(rate_limiter_default)])
async def simulate_incident(request: Request, incident_data: IncidentCreate):
    try:
        trace_id = get_trace_id()
        from apps.context_service import ContextBuilder
        full_context = await ContextBuilder().build_context(incident_data)
        return {"status": "success", "incident": incident_data.model_dump(), "context": full_context,
                "message": "Context built successfully.", "trace_id": trace_id}
    except Exception as exc:
        logger.error(f"Simulation failed: {str(exc)}", trace_id=get_trace_id())
        raise HTTPException(status_code=500, detail=str(exc))


@router.post("/incidents/analyze", dependencies=[Depends(rate_limiter_strict)])
async def analyze_incident(request: Request, incident_data: IncidentCreate):
    try:
        trace_id = get_trace_id()
        from apps.context_service import ContextBuilder
        from apps.orchestrator.runtime import DurableWorkflowRuntime

        full_context = await ContextBuilder().build_context(incident_data)
        incident_id = str(uuid4())
        summary = full_context.get("summary", {})
        evidence_summary = (
            f"Service: {incident_data.service}\n"
            f"Log count: {summary.get('log_count', 0)}\n"
            f"Metric count: {summary.get('metric_count', 0)}\n"
            f"Alert count: {summary.get('alert_count', 0)}\n"
            f"Average CPU: {summary.get('avg_cpu', 'N/A')}\n"
            f"Average Memory: {summary.get('avg_memory', 'N/A')}"
        )
        initial_state = {
            "incident_id": incident_id,
            "evidence_summary": evidence_summary,
            "service_name": incident_data.service,
            "context": full_context,
            "messages": [],
            "findings": [],
            "confidence": 0.0,
        }
        async with AsyncSessionLocal() as db:
            result = await DurableWorkflowRuntime(db).start(initial_state)
        return {
            "status": "success", "incident": incident_data.model_dump(), "incident_id": incident_id,
            "context": result.get("context", {}), "live_evidence": result.get("live_evidence", {}),
            "rag_results": result.get("knowledge_results", []), "similar_incidents": result.get("memory_results", []),
            "analysis": {"triage_result": result.get("triage_result"), "analysis_results": result.get("analysis_results", []),
                         "final_plan": result.get("final_plan"), "messages": result.get("messages", []), "findings": result.get("findings", [])},
            "evaluation": result.get("evaluation"), "decision": result.get("decision"), "approval": result.get("approval"),
            "execution": result.get("execution_result"), "verification": result.get("verification_result"), "trace_id": trace_id,
        }
    except Exception as exc:
        logger.error(f"Analysis failed: {str(exc)}", trace_id=get_trace_id())
        raise HTTPException(status_code=500, detail=str(exc))
