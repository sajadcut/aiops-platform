from __future__ import annotations

from typing import List, Optional

from fastapi import APIRouter, Depends, Query

from apps.audit_service.postgres import PostgreSQLAuditStore
from apps.security.auth import require_permission
from database import AsyncSessionLocal

router = APIRouter()


@router.get("/audit/events")
async def list_audit_events(
    incident_id: Optional[str] = Query(default=None),
    limit: int = Query(default=100, ge=1, le=500),
    _identity=Depends(require_permission("read:audit")),
) -> List[dict]:
    async with AsyncSessionLocal() as db:
        return await PostgreSQLAuditStore(db).list(incident_id=incident_id, limit=limit)
