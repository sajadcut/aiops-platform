from __future__ import annotations

from uuid import UUID
from fastapi import APIRouter, HTTPException, Query
from sqlalchemy import select, desc

from database import AsyncSessionLocal
from domain.models import Incident, Evidence, Finding
from apps.rag_service import KnowledgeRAGService
from apps.memory_service import OperationalMemoryService
from apps.audit_service import AuditService

router = APIRouter()


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
            "status": incident.status,
            "summary": incident.summary,
            "context": incident.context or {},
        }


@router.get("/incidents/{incident_id}/evidence")
async def get_evidence(incident_id: UUID, limit: int = Query(default=100, le=500)):
    async with AsyncSessionLocal() as db:
        rows = (await db.execute(
            select(Evidence).where(Evidence.incident_id == incident_id).order_by(desc(Evidence.created_at)).limit(limit)
        )).scalars().all()
        return {"items": [
            {
                "id": str(row.id), "type": row.type.value if hasattr(row.type, "value") else str(row.type),
                "source": row.source, "query": row.query, "time_range": row.time_range,
                "reference": row.reference, "raw_data": row.raw_data, "confidence": row.confidence,
            } for row in rows
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
        row = (await db.execute(
            select(Finding).where(Finding.incident_id == incident_id).order_by(desc(Finding.created_at)).limit(1)
        )).scalars().first()
        if row is None:
            raise HTTPException(status_code=404, detail="No finding/plan recorded for incident")
        return {"incident_id": str(incident_id), "finding": {
            "agent": row.agent, "finding_type": row.finding_type,
            "statement": row.statement, "evidence_ids": row.evidence_ids,
            "confidence": row.confidence,
        }}


@router.get("/incidents/{incident_id}/verification")
async def get_verification(incident_id: UUID):
    events = AuditService.list_events(str(incident_id), limit=100)
    verification = [event for event in events if event.get("event_type") == "verification_completed"]
    if not verification:
        return {"incident_id": str(incident_id), "status": "not_recorded", "items": []}
    return {"incident_id": str(incident_id), "items": verification}


@router.get("/incidents/{incident_id}/audit")
async def get_incident_audit(incident_id: UUID):
    return {"incident_id": str(incident_id), "items": AuditService.list_events(str(incident_id), 200)}
