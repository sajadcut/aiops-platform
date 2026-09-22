from __future__ import annotations

from typing import Any, Dict

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import text

from apps.memory_service import OperationalMemoryService
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
                          (SELECT COUNT(*) FROM approvals WHERE status='consumed') AS approvals_consumed,
                          (SELECT COUNT(*) FROM approvals WHERE status='rejected') AS approvals_rejected,
                          (SELECT COUNT(*) FROM audit_events) AS audit_events,
                          (SELECT COUNT(*) FROM audit_events WHERE event_type='execution_completed' AND LOWER(COALESCE(metadata->>'success',''))='true') AS execution_success,
                          (SELECT COUNT(*) FROM audit_events WHERE event_type='execution_completed' AND LOWER(COALESCE(metadata->>'success',''))<>'true' AND LOWER(COALESCE(metadata->>'blocked',''))<>'true') AS execution_failed,
                          (SELECT COUNT(*) FROM audit_events WHERE event_type='execution_completed' AND LOWER(COALESCE(metadata->>'blocked',''))='true') AS execution_blocked,
                          (SELECT COUNT(*) FROM audit_events WHERE event_type='verification_completed' AND LOWER(COALESCE(metadata->>'status','')) IN ('success','succeeded','verified')) AS verification_success,
                          (SELECT COUNT(*) FROM audit_events WHERE event_type='verification_completed' AND LOWER(COALESCE(metadata->>'status','')) IN ('failed','failure')) AS verification_failed,
                          (SELECT COUNT(*) FROM audit_events WHERE event_type='verification_completed' AND LOWER(COALESCE(metadata->>'status',''))='partial') AS verification_partial,
                          (SELECT COUNT(*) FROM audit_events WHERE event_type='verification_completed' AND LOWER(COALESCE(metadata->>'status',''))='inconclusive') AS verification_inconclusive,
                          (SELECT COUNT(*) FROM audit_events WHERE event_type='memory_writeback' AND LOWER(COALESCE(metadata->>'persisted',''))='true') AS memory_persisted,
                          (SELECT COUNT(*) FROM audit_events WHERE event_type='memory_writeback' AND LOWER(COALESCE(metadata->>'persisted',''))='false') AS memory_not_persisted,
                          (SELECT AVG(confidence) FROM findings WHERE confidence IS NOT NULL) AS mean_confidence
                        """
                    )
                )
            ).mappings().one()

            recent = (
                await db.execute(
                    text(
                        "SELECT event_id,event_type,incident_id,actor,action,status,metadata,created_at "
                        "FROM audit_events ORDER BY created_at DESC LIMIT 50"
                    )
                )
            ).mappings().all()
            memory_stats = await OperationalMemoryService(db).stats()

        result = dict(row)
        for key in (
            "incidents_total",
            "incidents_active",
            "incidents_critical",
            "approvals_pending",
            "approvals_approved",
            "approvals_consumed",
            "approvals_rejected",
            "audit_events",
            "execution_success",
            "execution_failed",
            "execution_blocked",
            "verification_success",
            "verification_failed",
            "verification_partial",
            "verification_inconclusive",
            "memory_persisted",
            "memory_not_persisted",
        ):
            result[key] = int(result[key] or 0)

        result["incidents_open"] = result["incidents_active"]
        result["successful_remediations"] = result["verification_success"]
        result["failed_verifications"] = result["verification_failed"]
        result["mean_confidence"] = float(result["mean_confidence"] or 0.0)

        verification_conclusive = result["verification_success"] + result["verification_failed"]
        verification_total = (
            verification_conclusive
            + result["verification_partial"]
            + result["verification_inconclusive"]
        )
        execution_total = (
            result["execution_success"]
            + result["execution_failed"]
            + result["execution_blocked"]
        )
        result["automation_success_rate"] = (
            result["verification_success"] / verification_conclusive
            if verification_conclusive
            else 0.0
        )
        result["verification_conclusive_rate"] = (
            verification_conclusive / verification_total if verification_total else 0.0
        )
        result["execution_success_rate"] = (
            result["execution_success"] / execution_total if execution_total else 0.0
        )
        result["recent_audit"] = [dict(item) for item in recent]
        result["operational_memory"] = memory_stats
        result["memory_entries_total"] = int(memory_stats["entries_total"])
        result["memory_entries_active"] = int(memory_stats["active"])
        result["memory_embedding_ready"] = int(
            memory_stats["embedding_ready_current_contract"]
        )
        result["memory_embedding_failed"] = int(memory_stats["embedding_failed"])
        result["memory_embedding_pending"] = int(memory_stats["embedding_pending"])
        result["data_status"] = "live"
        return result
    except Exception as exc:
        raise HTTPException(status_code=503, detail="dashboard_data_unavailable") from exc
