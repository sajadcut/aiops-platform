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
                               (SELECT a.action FROM approvals a WHERE a.incident_id=i.id ORDER BY a.created_at DESC LIMIT 1) AS approval_action,
                               (SELECT a.created_at FROM approvals a WHERE a.incident_id=i.id ORDER BY a.created_at DESC LIMIT 1) AS approval_created_at,
                               (SELECT a.approved_at FROM approvals a WHERE a.incident_id=i.id ORDER BY a.created_at DESC LIMIT 1) AS approved_at,
                               (SELECT COALESCE((a.metadata->>'binding_complete')::boolean, false) FROM approvals a WHERE a.incident_id=i.id ORDER BY a.created_at DESC LIMIT 1) AS binding_complete,
                               (SELECT a.metadata->>'tool_name' FROM approvals a WHERE a.incident_id=i.id ORDER BY a.created_at DESC LIMIT 1) AS execution_tool,
                               (SELECT a.metadata->>'target' FROM approvals a WHERE a.incident_id=i.id ORDER BY a.created_at DESC LIMIT 1) AS execution_target,
                               (SELECT a.metadata->>'runbook_id' FROM approvals a WHERE a.incident_id=i.id ORDER BY a.created_at DESC LIMIT 1) AS runbook_id,
                               (SELECT a.metadata->>'runbook_version' FROM approvals a WHERE a.incident_id=i.id ORDER BY a.created_at DESC LIMIT 1) AS runbook_version,
                               (SELECT a.metadata->>'environment' FROM approvals a WHERE a.incident_id=i.id ORDER BY a.created_at DESC LIMIT 1) AS environment,
                               (SELECT ae.metadata->>'decision' FROM audit_events ae WHERE ae.incident_id=i.id AND ae.event_type='decision_made' ORDER BY ae.created_at DESC LIMIT 1) AS decision,
                               (SELECT ae.metadata->>'risk' FROM audit_events ae WHERE ae.incident_id=i.id AND ae.event_type='decision_made' ORDER BY ae.created_at DESC LIMIT 1) AS risk_level,
                               (SELECT CASE
                                    WHEN LOWER(COALESCE(ae.metadata->>'blocked',''))='true' THEN 'blocked'
                                    WHEN LOWER(COALESCE(ae.metadata->>'success',''))='true' THEN 'success'
                                    ELSE 'failed'
                                END FROM audit_events ae WHERE ae.incident_id=i.id AND ae.event_type='execution_completed' ORDER BY ae.created_at DESC LIMIT 1) AS execution_status,
                               (SELECT ae.metadata->>'status' FROM audit_events ae WHERE ae.incident_id=i.id AND ae.event_type='verification_completed' ORDER BY ae.created_at DESC LIMIT 1) AS verification_status,
                               (SELECT ae.metadata->>'confidence' FROM audit_events ae WHERE ae.incident_id=i.id AND ae.event_type='verification_completed' ORDER BY ae.created_at DESC LIMIT 1) AS verification_confidence,
                               (SELECT CASE
                                    WHEN LOWER(COALESCE(ae.metadata->>'persisted',''))='true' THEN 'persisted'
                                    WHEN LOWER(COALESCE(ae.metadata->>'persisted',''))='false' THEN 'not_persisted'
                                    ELSE NULL
                                END FROM audit_events ae WHERE ae.incident_id=i.id AND ae.event_type='memory_writeback' ORDER BY ae.created_at DESC LIMIT 1) AS memory_status
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
                    "approval_status": (
                        row["approval_status"].value
                        if hasattr(row["approval_status"], "value")
                        else (str(row["approval_status"]) if row["approval_status"] is not None else None)
                    ),
                    "confidence": float(row["confidence"] or 0.0),
                    "verification_confidence": (
                        float(row["verification_confidence"])
                        if row["verification_confidence"] not in (None, "")
                        else None
                    ),
                    "started_at": row["started_at"].isoformat() if row["started_at"] else None,
                    "created_at": row["created_at"].isoformat() if row["created_at"] else None,
                    "approval_created_at": row["approval_created_at"].isoformat() if row["approval_created_at"] else None,
                    "approved_at": row["approved_at"].isoformat() if row["approved_at"] else None,
                }
                for row in rows
            ],
            "data_status": "live",
        }
    except Exception as exc:
        raise HTTPException(status_code=503, detail="incident_dashboard_unavailable") from exc


@router.get("/dashboard/services")
async def dashboard_services(
    limit: int = Query(default=50, ge=1, le=200),
    _identity=Depends(require_permission("read:incident")),
):
    """Service-centric operational health derived only from durable incident/governance state."""
    try:
        async with AsyncSessionLocal() as db:
            rows = (
                await db.execute(
                    text(
                        """
                        WITH incident_health AS (
                            SELECT
                                i.id,
                                COALESCE(NULLIF(i.service, ''), 'unknown') AS service,
                                LOWER(i.status::text) AS status,
                                LOWER(COALESCE(i.severity, 'unknown')) AS severity,
                                i.summary,
                                i.created_at,
                                COALESCE((SELECT AVG(f.confidence) FROM findings f WHERE f.incident_id=i.id), 0) AS confidence,
                                (SELECT a.status FROM approvals a WHERE a.incident_id=i.id ORDER BY a.created_at DESC LIMIT 1) AS approval_status,
                                (SELECT CASE
                                    WHEN LOWER(COALESCE(ae.metadata->>'blocked',''))='true' THEN 'blocked'
                                    WHEN LOWER(COALESCE(ae.metadata->>'success',''))='true' THEN 'success'
                                    ELSE 'failed'
                                END FROM audit_events ae WHERE ae.incident_id=i.id AND ae.event_type='execution_completed' ORDER BY ae.created_at DESC LIMIT 1) AS execution_status,
                                (SELECT LOWER(COALESCE(ae.metadata->>'status','')) FROM audit_events ae WHERE ae.incident_id=i.id AND ae.event_type='verification_completed' ORDER BY ae.created_at DESC LIMIT 1) AS verification_status,
                                (SELECT LOWER(COALESCE(ae.metadata->>'persisted','')) FROM audit_events ae WHERE ae.incident_id=i.id AND ae.event_type='memory_writeback' ORDER BY ae.created_at DESC LIMIT 1) AS memory_persisted
                            FROM incidents i
                        )
                        SELECT
                            service,
                            COUNT(*) AS incidents_total,
                            COUNT(*) FILTER (WHERE status NOT IN ('closed','resolved')) AS incidents_active,
                            COUNT(*) FILTER (WHERE severity='critical' AND status NOT IN ('closed','resolved')) AS critical_active,
                            COUNT(*) FILTER (WHERE severity='high' AND status NOT IN ('closed','resolved')) AS high_active,
                            COUNT(*) FILTER (WHERE approval_status='pending') AS approvals_pending,
                            COUNT(*) FILTER (WHERE approval_status='approved') AS approvals_approved,
                            COUNT(*) FILTER (WHERE execution_status='failed') AS failed_executions,
                            COUNT(*) FILTER (WHERE verification_status IN ('failed','failure')) AS failed_verifications,
                            COUNT(*) FILTER (WHERE verification_status='partial') AS partial_verifications,
                            COUNT(*) FILTER (WHERE verification_status='inconclusive') AS inconclusive_verifications,
                            COUNT(*) FILTER (WHERE verification_status IN ('success','succeeded','verified')) AS successful_verifications,
                            COUNT(*) FILTER (WHERE memory_persisted='true') AS memory_persisted,
                            AVG(confidence) FILTER (WHERE status NOT IN ('closed','resolved')) AS mean_active_confidence,
                            MAX(created_at) AS last_incident_at,
                            (ARRAY_AGG(summary ORDER BY created_at DESC))[1] AS latest_summary
                        FROM incident_health
                        GROUP BY service
                        ORDER BY critical_active DESC, high_active DESC, incidents_active DESC, last_incident_at DESC
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
                    "incidents_total": int(row["incidents_total"] or 0),
                    "incidents_active": int(row["incidents_active"] or 0),
                    "critical_active": int(row["critical_active"] or 0),
                    "high_active": int(row["high_active"] or 0),
                    "approvals_pending": int(row["approvals_pending"] or 0),
                    "approvals_approved": int(row["approvals_approved"] or 0),
                    "failed_executions": int(row["failed_executions"] or 0),
                    "failed_verifications": int(row["failed_verifications"] or 0),
                    "partial_verifications": int(row["partial_verifications"] or 0),
                    "inconclusive_verifications": int(row["inconclusive_verifications"] or 0),
                    "successful_verifications": int(row["successful_verifications"] or 0),
                    "memory_persisted": int(row["memory_persisted"] or 0),
                    "mean_active_confidence": float(row["mean_active_confidence"] or 0.0),
                    "last_incident_at": row["last_incident_at"].isoformat() if row["last_incident_at"] else None,
                }
                for row in rows
            ],
            "data_status": "live",
        }
    except Exception as exc:
        raise HTTPException(status_code=503, detail="service_dashboard_unavailable") from exc
