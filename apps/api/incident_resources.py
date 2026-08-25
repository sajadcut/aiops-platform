from __future__ import annotations

from uuid import UUID
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import desc, select, text

from database import AsyncSessionLocal
from domain.models import Incident, Evidence, Finding
from apps.rag_service import KnowledgeRAGService
from apps.memory_service import OperationalMemoryService
from apps.audit_service.postgres import PostgreSQLAuditStore
from apps.orchestrator.workflow_store import WorkflowCheckpointStore
from apps.security.auth import require_permission

router = APIRouter(dependencies=[Depends(require_permission("read:incident"))])


@router.get("/incidents/{incident_id}/context")
async def get_context(incident_id: UUID):
    async with AsyncSessionLocal() as db:
        incident = await db.get(Incident, incident_id)
        if incident is None:
            raise HTTPException(status_code=404, detail="Incident not found")
        return {
            "incident_id": str(incident.id),
            "service": incident.service,
            "severity": incident.severity,
            "status": incident.status.value if hasattr(incident.status, "value") else str(incident.status),
            "summary": incident.summary,
            "context": incident.context or {},
            "started_at": incident.started_at.isoformat() if incident.started_at else None,
        }


@router.get("/incidents/{incident_id}/evidence")
async def get_evidence(incident_id: UUID, limit: int = Query(default=100, le=500)):
    async with AsyncSessionLocal() as db:
        rows = (
            await db.execute(
                select(Evidence)
                .where(Evidence.incident_id == incident_id)
                .order_by(desc(Evidence.created_at))
                .limit(limit)
            )
        ).scalars().all()
        return {"items": [
            {
                "id": str(row.id),
                "type": row.type.value if hasattr(row.type, "value") else str(row.type),
                "source": row.source,
                "query": row.query,
                "time_range": row.time_range,
                "reference": row.reference,
                "raw_data": row.raw_data,
                "confidence": row.confidence,
            }
            for row in rows
        ]}


@router.get("/incidents/{incident_id}/knowledge")
async def get_knowledge(incident_id: UUID, limit: int = Query(default=5, le=20)):
    async with AsyncSessionLocal() as db:
        incident = await db.get(Incident, incident_id)
        if incident is None:
            raise HTTPException(status_code=404, detail="Incident not found")
        query = f"{incident.service or ''} {incident.summary or ''}".strip()
        return {"items": await KnowledgeRAGService(db).search(query, limit=limit)}


@router.get("/incidents/{incident_id}/memory")
async def get_memory(incident_id: UUID, limit: int = Query(default=5, le=20)):
    async with AsyncSessionLocal() as db:
        incident = await db.get(Incident, incident_id)
        if incident is None:
            raise HTTPException(status_code=404, detail="Incident not found")
        query = f"{incident.service or ''} {incident.summary or ''}".strip()
        return {"items": await OperationalMemoryService(db).search_similar(query, service_scope=incident.service, limit=limit)}


@router.get("/incidents/{incident_id}/plan")
async def get_plan(incident_id: UUID):
    async with AsyncSessionLocal() as db:
        rows = (
            await db.execute(
                select(Finding)
                .where(Finding.incident_id == incident_id)
                .order_by(desc(Finding.created_at))
                .limit(20)
            )
        ).scalars().all()
        if not rows:
            raise HTTPException(status_code=404, detail="No findings recorded for incident")
        return {"incident_id": str(incident_id), "findings": [
            {
                "agent": row.agent,
                "finding_type": row.finding_type,
                "statement": row.statement,
                "evidence_ids": row.evidence_ids,
                "confidence": row.confidence,
            }
            for row in rows
        ]}


@router.get("/incidents/{incident_id}/verification")
async def get_verification(incident_id: UUID):
    async with AsyncSessionLocal() as db:
        events = await PostgreSQLAuditStore(db).list(str(incident_id), limit=200)
    items = [event for event in events if event.get("event_type") == "verification_completed"]
    return {"incident_id": str(incident_id), "status": "recorded" if items else "not_recorded", "items": items}


@router.get("/incidents/{incident_id}/audit")
async def get_incident_audit(incident_id: UUID):
    async with AsyncSessionLocal() as db:
        items = await PostgreSQLAuditStore(db).list(str(incident_id), 200)
    return {"incident_id": str(incident_id), "items": items}


@router.get("/incidents/{incident_id}/lifecycle")
async def get_incident_lifecycle(incident_id: UUID):
    """Return durable workflow, decision, approval, execution and verification state for the operations UI."""
    async with AsyncSessionLocal() as db:
        incident = await db.get(Incident, incident_id)
        if incident is None:
            raise HTTPException(status_code=404, detail="Incident not found")
        checkpoint = await WorkflowCheckpointStore(db).load(str(incident_id))
        approval = (
            await db.execute(
                text(
                    "SELECT approval_id,action,risk_level,approver,status,metadata,created_at,approved_at,rejected_at "
                    "FROM approvals WHERE incident_id=:id ORDER BY created_at DESC LIMIT 1"
                ),
                {"id": str(incident_id)},
            )
        ).mappings().first()
        audits = await PostgreSQLAuditStore(db).list(str(incident_id), 200)

    state = (checkpoint or {}).get("state") or {}
    return {
        "incident_id": str(incident_id),
        "checkpoint_status": (checkpoint or {}).get("status"),
        "checkpoint_version": (checkpoint or {}).get("version"),
        "current_node": state.get("current_node"),
        "final_plan": state.get("final_plan"),
        "decision": state.get("decision"),
        "approval": dict(approval) if approval else state.get("approval"),
        "execution": state.get("execution_result"),
        "verification": state.get("verification_result"),
        "terminal_reason": state.get("terminal_reason"),
        "audit": audits,
    }
