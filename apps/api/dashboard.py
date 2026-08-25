from __future__ import annotations

from typing import Any, Dict

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import text

from apps.security.auth import require_permission
from database import AsyncSessionLocal

router = APIRouter()


@router.get("/dashboard/summary")
async def dashboard_summary(_identity=Depends(require_permission("read:incident"))) -> Dict[str, Any]:
    """Return live PostgreSQL-backed KPIs. Database failures are never converted to fake zeroes."""
    try:
        async with AsyncSessionLocal() as db:
            row = (
                await db.execute(
                    text(
                        """
                        SELECT
                          (SELECT COUNT(*) FROM incidents) AS incidents_total,
                          (SELECT COUNT(*) FROM incidents WHERE LOWER(status::text) NOT IN ('closed','resolved')) AS incidents_active,
                          (SELECT COUNT(*) FROM incidents WHERE LOWER(severity)='critical' AND LOWER(status::text) NOT IN ('closed','resolved')) AS incidents_critical,
                          (SELECT COUNT(*) FROM approvals WHERE status='pending') AS approvals_pending,
                          (SELECT COUNT(*) FROM approvals WHERE status='approved') AS approvals_approved,
                          (SELECT COUNT(*) FROM audit_events) AS audit_events,
                          (SELECT COUNT(*) FROM audit_events WHERE event_type='verification_completed' AND LOWER(COALESCE(metadata->>'status','')) IN ('success','succeeded','verified')) AS verification_success,
                          (SELECT COUNT(*) FROM audit_events WHERE event_type='verification_completed' AND LOWER(COALESCE(metadata->>'status','')) IN ('failed','failure')) AS verification_failed,
                          (SELECT AVG(confidence) FROM findings WHERE confidence IS NOT NULL) AS mean_confidence
                        """
                    )
                )
            ).mappings().one()

            recent = (
                await db.execute(
                    text(
                        "SELECT event_id,event_type,incident_id,action,status,metadata,created_at "
                        "FROM audit_events ORDER BY created_at DESC LIMIT 30"
                    )
                )
            ).mappings().all()

        result = dict(row)
        result["incidents_open"] = int(result["incidents_active"] or 0)
        result["successful_remediations"] = int(result["verification_success"] or 0)
        result["failed_verifications"] = int(result["verification_failed"] or 0)
        result["mean_confidence"] = float(result["mean_confidence"] or 0.0)
        verified_total = int(result["verification_success"] or 0) + int(result["verification_failed"] or 0)
        result["automation_success_rate"] = (
            int(result["verification_success"] or 0) / verified_total if verified_total else 0.0
        )
        result["recent_audit"] = [dict(item) for item in recent]
        result["data_status"] = "live"
        return result
    except Exception as exc:
        raise HTTPException(status_code=503, detail="dashboard_data_unavailable") from exc
