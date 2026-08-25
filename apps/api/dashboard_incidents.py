from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import text

from apps.security.auth import require_permission
from database import AsyncSessionLocal

router = APIRouter()


@router.get("/dashboard/incidents")
async def dashboard_incidents(
    limit: int = Query(default=50, ge=1, le=200),
    _identity=Depends(require_permission("read:incident")),
):
    """Operational incident list enriched from durable governance/audit state."""
    try:
        async with AsyncSessionLocal() as db:
            rows = (
                await db.execute(
                    text(
                        """
                        SELECT i.id, i.service, i.status, i.severity, i.summary, i.started_at, i.created_at,
                               COALESCE((SELECT AVG(f.confidence) FROM findings f WHERE f.incident_id=i.id),0) AS confidence,
                               (SELECT a.approval_id FROM approvals a WHERE a.incident_id=i.id ORDER BY a.created_at DESC LIMIT 1) AS approval_id,
                               (SELECT a.status FROM approvals a WHERE a.incident_id=i.id ORDER BY a.created_at DESC LIMIT 1) AS approval_status,
                               (SELECT ae.metadata->>'decision' FROM audit_events ae WHERE ae.incident_id=i.id AND ae.event_type='decision_made' ORDER BY ae.created_at DESC LIMIT 1) AS decision,
                               (SELECT ae.metadata->>'risk' FROM audit_events ae WHERE ae.incident_id=i.id AND ae.event_type='decision_made' ORDER BY ae.created_at DESC LIMIT 1) AS risk_level,
                               (SELECT ae.metadata->>'status' FROM audit_events ae WHERE ae.incident_id=i.id AND ae.event_type='verification_completed' ORDER BY ae.created_at DESC LIMIT 1) AS verification_status
                        FROM incidents i
                        ORDER BY i.created_at DESC
                        LIMIT :limit
                        """
                    ),
                    {"limit": limit},
                )
            ).mappings().all()
        return {
            "items": [
                {
                    **dict(row),
                    "id": str(row["id"]),
                    "status": row["status"].value if hasattr(row["status"], "value") else str(row["status"]),
                    "approval_id": str(row["approval_id"]) if row["approval_id"] else None,
                    "confidence": float(row["confidence"] or 0.0),
                    "started_at": row["started_at"].isoformat() if row["started_at"] else None,
                    "created_at": row["created_at"].isoformat() if row["created_at"] else None,
                }
                for row in rows
            ],
            "data_status": "live",
        }
    except Exception as exc:
        raise HTTPException(status_code=503, detail="incident_dashboard_unavailable") from exc
