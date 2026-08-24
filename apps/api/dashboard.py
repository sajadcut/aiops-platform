from __future__ import annotations

from typing import Any, Dict

from fastapi import APIRouter
from sqlalchemy import text

from database import AsyncSessionLocal

router = APIRouter()


@router.get("/dashboard/summary")
async def dashboard_summary() -> Dict[str, Any]:
    async with AsyncSessionLocal() as db:
        queries = {
            "incidents_total": "SELECT COUNT(*) FROM incidents",
            "incidents_open": "SELECT COUNT(*) FROM incidents WHERE status NOT IN ('closed','resolved')",
            "audit_events": "SELECT COUNT(*) FROM audit_events",
            "approvals_pending": "SELECT COUNT(*) FROM approvals WHERE status='pending'",
            "approvals_approved": "SELECT COUNT(*) FROM approvals WHERE status='approved'",
        }
        result = {}
        for key, sql in queries.items():
            try:
                result[key] = int((await db.execute(text(sql))).scalar() or 0)
            except Exception:
                result[key] = 0
        try:
            result["verification_success"] = int((await db.execute(text("SELECT COUNT(*) FROM verification_results WHERE status='success'"))).scalar() or 0)
            result["verification_failed"] = int((await db.execute(text("SELECT COUNT(*) FROM verification_results WHERE status='failed'"))).scalar() or 0)
        except Exception:
            result["verification_success"] = 0
            result["verification_failed"] = 0
        total = result["verification_success"] + result["verification_failed"]
        result["automation_success_rate"] = (result["verification_success"] / total) if total else 0.0
        result["recent_audit"] = []
        try:
            rows = (await db.execute(text("SELECT event_id,event_type,incident_id,status,created_at FROM audit_events ORDER BY created_at DESC LIMIT 50"))).mappings().all()
            result["recent_audit"] = [dict(row) for row in rows]
        except Exception:
            pass
        return result
