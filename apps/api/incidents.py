from __future__ import annotations

from fastapi import APIRouter, HTTPException, Depends, Request
from pydantic import BaseModel, Field
from sqlalchemy import select, desc
from domain.schemas import IncidentCreate
from domain.contracts.logging import logger
from domain.contracts.rate_limit import rate_limiter_default, rate_limiter_strict
from domain.contracts.context import get_trace_id
from domain.contracts.config import settings
from database import AsyncSessionLocal
from domain.models import Incident, Finding
from apps.approval_service.postgres import PostgreSQLApprovalStore
from apps.security.auth import require_permission
from uuid import UUID, uuid4
from datetime import datetime, timezone

router = APIRouter()


@router.post("/incidents/simulate", dependencies=[Depends(rate_limiter_default)])
async def simulate_incident(
    request: Request,
    incident_data: IncidentCreate,
    _user=Depends(require_permission("read:incident")),
):
    if settings.APP_ENV == "production":
        raise HTTPException(status_code=404, detail="not_found")
    try:
        trace_id = get_trace_id()
        from apps.context_service import ContextBuilder
        full_context = await ContextBuilder().build_context(incident_data)
        return {
            "status": "success",
            "incident": incident_data.model_dump(),
            "context": full_context,
            "message": "Simulation only; no execution path was invoked.",
            "trace_id": trace_id,
        }
    except Exception as exc:
        logger.error(f"Simulation failed: {exc}", trace_id=get_trace_id())
        raise HTTPException(status_code=500, detail="simulation_failed") from exc


@router.post("/incidents/analyze", dependencies=[Depends(rate_limiter_strict)])
async def analyze_incident(
    request: Request,
    incident_data: IncidentCreate,
    _user=Depends(require_permission("read:incident")),
):
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
            "status": "success",
            "incident": incident_data.model_dump(),
            "incident_id": incident_id,
            "context": result.get("context", {}),
            "live_evidence": result.get("live_evidence", {}),
            "rag_results": result.get("knowledge_results", []),
            "similar_incidents": result.get("memory_results", []),
            "analysis": {
                "triage_result": result.get("triage_result"),
                "analysis_results": result.get("analysis_results", []),
                "final_plan": result.get("final_plan"),
                "messages": result.get("messages", []),
                "findings": result.get("findings", []),
            },
            "evaluation": result.get("evaluation"),
            "decision": result.get("decision"),
            "approval": result.get("approval"),
            "execution": result.get("execution_result"),
            "verification": result.get("verification_result"),
            "trace_id": trace_id,
        }
    except HTTPException:
        raise
    except Exception as exc:
        logger.error(f"Analysis failed: {exc}", trace_id=get_trace_id())
        raise HTTPException(status_code=500, detail="analysis_failed") from exc


class RemediationRequest(BaseModel):
    reason: str = Field(default="Operator requested incident remediation", min_length=3, max_length=1000)
    risk_level: str = Field(default="medium", pattern="^(low|medium|high)$")
    approver: str = Field(default="Team-Lead", min_length=2, max_length=255)


@router.post("/incidents/{incident_id}/remediate")
async def request_remediation(
    incident_id: UUID,
    payload: RemediationRequest,
    _user=Depends(require_permission("approve:low_risk")),
):
    """Create a durable approval request; this endpoint never executes a tool."""
    async with AsyncSessionLocal() as db:
        incident = await db.get(Incident, incident_id)
        if incident is None:
            raise HTTPException(status_code=404, detail="Incident not found")

        finding = (
            await db.execute(
                select(Finding)
                .where(Finding.incident_id == incident_id)
                .order_by(desc(Finding.created_at))
                .limit(1)
            )
        ).scalars().first()
        action = finding.statement if finding else f"Remediate incident for service {incident.service or 'unknown'}"
        approval_id = str(uuid4())
        record = {
            "approval_id": approval_id,
            "incident_id": str(incident_id),
            "action": action[:1000],
            "risk_level": payload.risk_level,
            "approver": payload.approver,
            "status": "pending",
            "metadata": {"source": "dashboard", "reason": payload.reason},
            "created_at": datetime.now(timezone.utc),
            "approved_at": None,
            "rejected_at": None,
        }
        await PostgreSQLApprovalStore(db).save(record)
        return {
            "status": "approval_required",
            "incident_id": str(incident_id),
            "approval_id": approval_id,
            "action": action,
            "risk_level": payload.risk_level,
            "approver": payload.approver,
            "message": "Remediation request created. Execution remains blocked until approval.",
        }
