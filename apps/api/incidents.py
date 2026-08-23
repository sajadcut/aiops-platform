# ============================================================
# FILE: app/api/incidents.py
# ============================================================

from fastapi import APIRouter, HTTPException, Depends, Request
from domain.schemas import IncidentCreate
from domain.contracts.logging import logger
from domain.contracts.rate_limit import rate_limiter_default, rate_limiter_strict
from domain.contracts.context import get_trace_id
from database import AsyncSessionLocal
from uuid import uuid4

router = APIRouter()


@router.post(
    "/incidents/simulate",
    dependencies=[Depends(rate_limiter_default)],
)
async def simulate_incident(
    request: Request,
    incident_data: IncidentCreate,
):
    try:
        trace_id = get_trace_id()
        logger.info(
            f"Simulating incident for service: {incident_data.service}",
            trace_id=trace_id,
        )

        from apps.context_service import ContextBuilder
        builder = ContextBuilder()
        full_context = await builder.build_context(incident_data)

        return {
            "status": "success",
            "incident": incident_data.model_dump(),
            "context": full_context,
            "message": "Context built successfully.",
            "trace_id": trace_id,
        }

    except Exception as exc:
        logger.error(f"Simulation failed: {str(exc)}", trace_id=get_trace_id())
        raise HTTPException(status_code=500, detail=str(exc))


@router.post(
    "/incidents/analyze",
    dependencies=[Depends(rate_limiter_strict)],
)
async def analyze_incident(
    request: Request,
    incident_data: IncidentCreate,
):
    try:
        trace_id = get_trace_id()
        logger.info(
            f"Analyzing incident for service: {incident_data.service}",
            trace_id=trace_id,
        )

        from apps.context_service import ContextBuilder
        from apps.orchestrator.graph import WorkflowOrchestrator
        from apps.decision_engine import DecisionEngine
        from apps.rag_service import KnowledgeRAGService
        from apps.memory_service import OperationalMemoryService
        from apps.approval_service import ApprovalService

        builder = ContextBuilder()
        full_context = await builder.build_context(incident_data)

        async with AsyncSessionLocal() as db:
            rag_service = KnowledgeRAGService(db)
            memory_service = OperationalMemoryService(db)

            knowledge_results = await rag_service.search(
                query=f"{incident_data.service} {incident_data.summary}",
                limit=3,
            )

            similar_incidents = await memory_service.search_similar(
                query=f"{incident_data.service} {incident_data.summary}",
                service_scope=incident_data.service,
                limit=3,
            )

        full_context["knowledge"] = knowledge_results
        full_context["similar_incidents"] = similar_incidents

        evidence_summary = full_context.get("summary", {})
        context_text = (
            f"Service: {incident_data.service}\n"
            f"Log count: {evidence_summary.get('log_count', 0)}\n"
            f"Metric count: {evidence_summary.get('metric_count', 0)}\n"
            f"Alert count: {evidence_summary.get('alert_count', 0)}\n"
            f"Average CPU: {evidence_summary.get('avg_cpu', 'N/A')}\n"
            f"Average Memory: {evidence_summary.get('avg_memory', 'N/A')}\n"
            f"Knowledge Results: {len(knowledge_results)} documents found\n"
            f"Similar Incidents: {len(similar_incidents)} found"
        )

        incident_id = str(uuid4())
        initial_state = {
            "incident_id": incident_id,
            "evidence_summary": context_text,
            "service_name": incident_data.service,
            "context": full_context,
            "messages": [],
            "findings": [],
            "confidence": 0.0,
        }

        orchestrator = WorkflowOrchestrator()
        result = await orchestrator.run(initial_state)

        decision_result = DecisionEngine.evaluate_plan(
            plan=result.get("final_plan", ""),
            findings=result.get("findings", []),
        )

        approval = None
        if decision_result.requires_approval and decision_result.action.value == "require_approval":
            approval = ApprovalService.create_request(
                incident_id=incident_id,
                action=result.get("final_plan", "investigate"),
                risk_level=decision_result.risk_level.value,
                approver=decision_result.suggested_approver or "Team-Lead",
                metadata={
                    "service": incident_data.service,
                    "trace_id": trace_id,
                    "confidence": decision_result.metadata.get("avg_confidence", 0.0),
                },
            )

        verification = {
            "status": "pending" if approval else "not_executed",
            "before_state": {},
            "after_state": {},
            "changes": [],
            "confidence": 0.0,
            "evidence_refs": [],
            "message": "Human approval is required before execution." if approval else "No execution was performed.",
        }

        return {
            "status": "success",
            "incident": incident_data.model_dump(),
            "incident_id": incident_id,
            "context_summary": {
                "log_count": evidence_summary.get("log_count", 0),
                "metric_count": evidence_summary.get("metric_count", 0),
                "alert_count": evidence_summary.get("alert_count", 0),
            },
            "rag_results": knowledge_results,
            "similar_incidents": similar_incidents,
            "analysis": {
                "triage_result": result.get("triage_result"),
                "analysis_results": result.get("analysis_results"),
                "final_plan": result.get("final_plan"),
                "messages": result.get("messages", []),
                "findings": result.get("findings", []),
            },
            "decision": decision_result.model_dump(),
            "approval": approval,
            "verification": verification,
            "trace_id": trace_id,
        }

    except Exception as exc:
        logger.error(f"Analysis failed: {str(exc)}", trace_id=get_trace_id())
        raise HTTPException(status_code=500, detail=str(exc))