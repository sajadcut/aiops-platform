from __future__ import annotations

from typing import Any, Dict, Optional
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession


class PostgreSQLApprovalStore:
    """Durable approval persistence for cross-process workflow resume."""

    def __init__(self, session: AsyncSession):
        self.session = session

    async def save(self, record: Dict[str, Any]) -> Dict[str, Any]:
        await self.session.execute(
            text(
                """
                INSERT INTO approvals
                (approval_id, incident_id, action, risk_level, approver, status, metadata, created_at, approved_at, rejected_at)
                VALUES (:approval_id, :incident_id, :action, :risk_level, :approver, :status, CAST(:metadata AS jsonb),
                        :created_at, :approved_at, :rejected_at)
                ON CONFLICT (approval_id) DO UPDATE SET status=EXCLUDED.status,
                    metadata=EXCLUDED.metadata, approved_at=EXCLUDED.approved_at,
                    rejected_at=EXCLUDED.rejected_at
                """
            )
        , record)
        await self.session.commit()
        return record

    async def get(self, approval_id: str) -> Optional[Dict[str, Any]]:
        row = (await self.session.execute(
            text("SELECT approval_id, incident_id, action, risk_level, approver, status, metadata, created_at, approved_at, rejected_at FROM approvals WHERE approval_id=:id"),
            {"id": approval_id},
        )).mappings().first()
        return dict(row) if row else None

    async def set_status(self, approval_id: str, status: str) -> Optional[Dict[str, Any]]:
        timestamp_column = "approved_at" if status == "approved" else "rejected_at" if status == "rejected" else None
        if timestamp_column:
            await self.session.execute(
                text(f"UPDATE approvals SET status=:status, {timestamp_column}=CURRENT_TIMESTAMP WHERE approval_id=:id"),
                {"status": status, "id": approval_id},
            )
        else:
            await self.session.execute(text("UPDATE approvals SET status=:status WHERE approval_id=:id"), {"status": status, "id": approval_id})
        await self.session.commit()
        return await self.get(approval_id)

    async def is_approved(self, approval_id: str) -> bool:
        record = await self.get(approval_id)
        return bool(record and record.get("status") == "approved")
