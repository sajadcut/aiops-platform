from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from domain.contracts.config import settings


class PostgreSQLApprovalStore:
    """Durable approval persistence with expiry and guarded transitions."""

    def __init__(self, session: AsyncSession):
        self.session = session

    async def save(self, record: Dict[str, Any]) -> Dict[str, Any]:
        params = dict(record)
        params["metadata"] = json.dumps(record.get("metadata") or {}, default=str)
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
            ),
            params,
        )
        await self.session.commit()
        return await self.get(str(record["approval_id"])) or record

    async def _get_raw(self, approval_id: str) -> Optional[Dict[str, Any]]:
        row = (
            await self.session.execute(
                text(
                    "SELECT approval_id, incident_id, action, risk_level, approver, status, metadata, "
                    "created_at, approved_at, rejected_at FROM approvals WHERE approval_id=:id"
                ),
                {"id": approval_id},
            )
        ).mappings().first()
        return dict(row) if row else None

    @staticmethod
    def _expired(record: Dict[str, Any]) -> bool:
        created_at = record.get("created_at")
        if created_at is None or settings.APPROVAL_TTL_SECONDS <= 0:
            return False
        if isinstance(created_at, str):
            created_at = datetime.fromisoformat(created_at.replace("Z", "+00:00"))
        if created_at.tzinfo is None:
            created_at = created_at.replace(tzinfo=timezone.utc)
        age = (datetime.now(timezone.utc) - created_at.astimezone(timezone.utc)).total_seconds()
        return age > settings.APPROVAL_TTL_SECONDS

    async def get(self, approval_id: str) -> Optional[Dict[str, Any]]:
        record = await self._get_raw(approval_id)
        if record and record.get("status") in {"pending", "approved"} and self._expired(record):
            await self.session.execute(
                text("UPDATE approvals SET status='expired' WHERE approval_id=:id AND status IN ('pending','approved')"),
                {"id": approval_id},
            )
            await self.session.commit()
            record = await self._get_raw(approval_id)
        return record

    async def set_status(self, approval_id: str, status: str) -> Optional[Dict[str, Any]]:
        if status not in {"approved", "rejected"}:
            raise ValueError("invalid_approval_status")
        current = await self.get(approval_id)
        if current is None:
            return None
        if current.get("status") == "expired":
            return current
        if current.get("status") != "pending":
            return current
        timestamp_column = "approved_at" if status == "approved" else "rejected_at"
        await self.session.execute(
            text(
                f"UPDATE approvals SET status=:status, {timestamp_column}=CURRENT_TIMESTAMP "
                "WHERE approval_id=:id AND status='pending'"
            ),
            {"status": status, "id": approval_id},
        )
        await self.session.commit()
        return await self._get_raw(approval_id)

    async def is_approved(self, approval_id: str) -> bool:
        record = await self.get(approval_id)
        return bool(record and record.get("status") == "approved")
