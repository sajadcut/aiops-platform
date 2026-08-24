from __future__ import annotations

from fastapi import APIRouter, Query
from sqlalchemy import desc, select

from database import AsyncSessionLocal
from domain.models import Incident

router = APIRouter()


@router.get("/dashboard/incidents")
async def dashboard_incidents(limit: int = Query(default=20, ge=1, le=100)):
    async with AsyncSessionLocal() as db:
        rows = (await db.execute(
            select(Incident).order_by(desc(Incident.created_at)).limit(limit)
        )).scalars().all()
        return {"items": [
            {
                "id": str(row.id),
                "service": row.service,
                "status": row.status,
                "severity": row.severity,
                "summary": row.summary,
                "created_at": row.created_at.isoformat() if row.created_at else None,
            }
            for row in rows
        ]}
