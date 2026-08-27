from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from domain.contracts.config import settings


class PostgreSQLApprovalStore:
    """Durable approval persistence with expiry, guarded transitions and one-time consumption."""

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
        return (datetime.now(timezone.utc) - created_at.astimezone(timezone.utc)).total_seconds() > settings.APPROVAL_TTL_SECONDS

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

    async def set_status(
        self,
        approval_id: str,
        status: str,
        *,
        metadata_patch: Optional[Dict[str, Any]] = None,
    ) -> Optional[Dict[str, Any]]:
        """Atomically transition a pending approval exactly once.

        Returns the transitioned row, or the current row when no pending row was
        available. Callers must treat any non-matching status as a conflict.
        """
        if status not in {"approved", "rejected"}:
            raise ValueError("invalid_approval_status")

        # Expiry is evaluated before the transition. get() persists expired state.
        current = await self.get(approval_id)
        if current is None or current.get("status") != "pending":
            return current

        patch = dict(metadata_patch or {})
        patch_json = json.dumps(patch, default=str)
        timestamp_column = "approved_at" if status == "approved" else "rejected_at"
        row = (
            await self.session.execute(
                text(
                    f"""
                    UPDATE approvals
                    SET status=:status,
                        {timestamp_column}=CURRENT_TIMESTAMP,
                        metadata=COALESCE(metadata, '{{}}'::jsonb) || CAST(:metadata_patch AS jsonb)
                    WHERE approval_id=:id AND status='pending'
                    RETURNING approval_id, incident_id, action, risk_level, approver, status,
                              metadata, created_at, approved_at, rejected_at
                    """
                ),
                {"status": status, "id": approval_id, "metadata_patch": patch_json},
            )
        ).mappings().first()
        await self.session.commit()
        return dict(row) if row else await self._get_raw(approval_id)

    async def consume(self, approval_id: str) -> Optional[Dict[str, Any]]:
        """Atomically consume an approved record exactly once before crossing the execution boundary."""
        current = await self.get(approval_id)
        if current is None or current.get("status") != "approved":
            return current
        row = (
            await self.session.execute(
                text(
                    "UPDATE approvals SET status='consumed' "
                    "WHERE approval_id=:id AND status='approved' "
                    "RETURNING approval_id, incident_id, action, risk_level, approver, status, metadata, created_at, approved_at, rejected_at"
                ),
                {"id": approval_id},
            )
        ).mappings().first()
        await self.session.commit()
        return dict(row) if row else await self._get_raw(approval_id)

    async def is_approved(self, approval_id: str) -> bool:
        record = await self.get(approval_id)
        return bool(record and record.get("status") == "approved")
