from __future__ import annotations

from fastapi import APIRouter
from apps.audit_service import AuditService

router = APIRouter()


@router.get("/dashboard/summary")
async def dashboard_summary():
    events = AuditService.list_events(limit=500)
    return {
        "incident_events": len({e.get("incident_id") for e in events if e.get("incident_id")}),
        "approval_requested": sum(e.get("event_type") == "approval_requested" for e in events),
        "execution_completed": sum(e.get("event_type") == "execution_completed" for e in events),
        "verification_completed": sum(e.get("event_type") == "verification_completed" for e in events),
        "events": events[-50:],
    }
