from fastapi import APIRouter, HTTPException, Depends, Request
from app.domain.schemas import IncidentCreate
from app.core.logging import logger
from app.core.rate_limit import rate_limiter_default, rate_limiter_strict
from app.core.context import get_trace_id
from app.infrastructure.database import AsyncSessionLocal
from uuid import uuid4

router = APIRouter()

@router.post("/incidents/simulate", dependencies=[Depends(rate_limiter_default)])
async def simulate_incident(request: Request, incident_data: IncidentCreate):
    try:
        trace_id = get_trace_id()
        logger.info(f"Simulating incident for service: {incident_data.service}", trace_id=trace_id)
        
        from app.services.context_builder import ContextBuilder
        builder = ContextBuilder()
        full_context = await builder.build_context(incident_data)
        
        return {
            "status": "success",
            "incident": incident_data.model_dump(),
            "context": full_context,
            "message": "Context built successfully.",
            "trace_id": trace_id
        }
    except Exception as e:
        logger.error(f"Simulation failed: {str(e)}", trace_id=get_trace_id())
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/incidents/analyze", dependencies=[Depends(rate_limiter_strict)])
async def analyze_incident(request: Request, incident_data: IncidentCreate):
    try:
        trace_id = get_trace_id()
        logger.info(f"Analyzing incident for service: {incident_data.service}", trace_id=trace_id)
        
        from app.services.context_builder import ContextBuilder
        from app.orchestrator.graph import WorkflowOrchestrator
        from app.services.decision_engine import DecisionEngine
        from app.services.verification_engine import VerificationEngine
        from app.services.knowledge_rag import KnowledgeRAGService
        from app.services.operational_memory import OperationalMemoryService
        
        # ۱. ساخت Context
        builder = ContextBuilder()
        full_context = await builder.build_context(incident_data)
        
        # ۲. جستجوی RAG و Memory (با دیتابیس)
        async with AsyncSessionLocal() as db:
            rag_service = KnowledgeRAGService(db)
            memory_service = OperationalMemoryService(db)
            
            knowledge_results = await rag_service.search(
                query=f"{incident_data.service} {incident_data.summary}",
                limit=3
            )
            
            similar_incidents = await memory_service.search_similar(
                query=f"{incident_data.service} {incident_data.summary}",
                service_scope=incident_data.service,
                limit=3
            )
        
        # ۳. اضافه کردن به Context
        full_context["knowledge"] = knowledge_results
        full_context["similar_incidents"] = similar_incidents
        
        # ۴. آماده‌سازی State برای Orchestrator
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
        
        initial_state = {
            "incident_id": str(uuid4()),
            "evidence_summary": context_text,
            "service_name": incident_data.service,
            "context": full_context,
            "messages": [],
            "findings": [],
            "confidence": 0.0
        }
        
        # ۵. اجرای Orchestrator
        orchestrator = WorkflowOrchestrator()
        result = await orchestrator.run(initial_state)
        
        # ۶. Decision Engine
        decision_result = DecisionEngine.evaluate_plan(
            plan=result.get("final_plan", ""),
            findings=result.get("findings", [])
        )
        
        # ۷. Verification Engine
        verification_result = await VerificationEngine.verify_action(
            action_plan=result.get("final_plan", ""),
            service=incident_data.service,
            before_context=full_context,
            after_context=None
        )
        
        # ۸. پاسخ نهایی
        return {
            "status": "success",
            "incident": incident_data.model_dump(),
            "context_summary": {
                "log_count": evidence_summary.get('log_count', 0),
                "metric_count": evidence_summary.get('metric_count', 0),
                "alert_count": evidence_summary.get('alert_count', 0),
            },
            "rag_results": knowledge_results,
            "similar_incidents": similar_incidents,
            "analysis": {
                "triage_result": result.get("triage_result"),
                "analysis_results": result.get("analysis_results"),
                "final_plan": result.get("final_plan"),
                "messages": result.get("messages", []),
                "findings": result.get("findings", [])
            },
            "decision": decision_result.model_dump(),
            "verification": verification_result.model_dump(),
            "trace_id": trace_id
        }
        
    except Exception as e:
        logger.error(f"Analysis failed: {str(e)}", trace_id=get_trace_id())
        raise HTTPException(status_code=500, detail=str(e))