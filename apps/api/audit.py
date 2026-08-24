from __future__ import annotations

from typing import List, Optional

from fastapi import APIRouter, Query

from apps.audit_service import AuditService

router = APIRouter()


@router.get("/audit/events")
async def list_audit_events(
    incident_id: Optional[str] = Query(default=None),
    limit: int = Query(default=100, ge=1, le=500),
) -> List[dict]:
    return AuditService.list_events(incident_id=incident_id, limit=limit)
