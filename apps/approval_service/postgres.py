"""Persistence امن Approval روی PostgreSQL.

Approval یک boolean ساده نیست؛ مجوز باید durable، زمان‌دار، دارای transition محدود و
یک‌بارمصرف باشد. این store وضعیت‌های pending/approved/rejected/expired/consumed را
نگه می‌دارد تا restart، race یا replay نتواند execution را بدون مجوز معتبر عبور دهد.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from domain.contracts.config import settings


def _db_timestamp(value: Any) -> Any:
    """Normalize ISO-8601 application timestamps for asyncpg TIMESTAMPTZ binds."""
    if value is None or isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str):
        raw = value.strip()
        if not raw:
            return None
        try:
            parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValueError("invalid_approval_timestamp") from exc
    else:
        return value
    if parsed is not None and parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


class PostgreSQLApprovalStore:
    """Approval durable با expiry، transition اتمیک و consume یک‌باره قبل از execution."""

    def __init__(self, session: AsyncSession):
        self.session = session

    async def _incident_source_recovered(self, incident_id: str) -> bool:
        row = (
            await self.session.execute(
                text("SELECT status, context FROM incidents WHERE id=:id"),
                {"id": incident_id},
            )
        ).mappings().first()
        if not row:
            return False
        context = row.get("context") or {}
        if isinstance(context, str):
            try:
                context = json.loads(context)
            except json.JSONDecodeError:
                context = {}
        marker = dict(context.get("source_recovery") or {}) if isinstance(context, dict) else {}
        return bool(str(row.get("status") or "").lower() == "resolved" and marker.get("incident_resolved"))

    async def save(self, record: Dict[str, Any]) -> Dict[str, Any]:
        """Create durable approval authority exactly once.

        Existing approval IDs are immutable through save(): terminal states such
        as consumed/rejected/expired must never be resurrected by a repeated
        persistence call. State transitions are allowed only through the
        dedicated compare-and-set transition methods.
        """
        record_to_save = dict(record)
        metadata = dict(record.get("metadata") or {})
        if (
            str(record_to_save.get("status") or "pending") in {"pending", "approved"}
            and await self._incident_source_recovered(str(record_to_save.get("incident_id") or ""))
        ):
            # A Recovery can race a slow RCA/Decision path. Persist the late
            # approval as rejected so no worker can later consume stale authority.
            record_to_save["status"] = "rejected"
            record_to_save["rejected_at"] = datetime.now(timezone.utc)
            metadata["cancelled_due_to_source_recovery"] = True

        params = dict(record_to_save)
        params["metadata"] = json.dumps(metadata, default=str)
        # ApprovalService intentionally exposes JSON-friendly ISO strings. asyncpg,
        # however, requires native datetime objects for TIMESTAMPTZ bind values.
        # Normalize exactly at the PostgreSQL adapter boundary so the domain/API
        # contract can remain serializable while persistence remains type-safe.
        params["created_at"] = (
            _db_timestamp(params.get("created_at"))
            or datetime.now(timezone.utc)
        )
        for field in ("approved_at", "rejected_at"):
            params[field] = _db_timestamp(params.get(field))
        await self.session.execute(
            text(
                """
                INSERT INTO approvals
                (approval_id, incident_id, action, risk_level, approver, status, metadata, created_at, approved_at, rejected_at)
                VALUES (:approval_id, :incident_id, :action, :risk_level, :approver, :status, CAST(:metadata AS jsonb),
                        :created_at, :approved_at, :rejected_at)
                ON CONFLICT (approval_id) DO NOTHING
                """
            ),
            params,
        )
        await self.session.commit()
        return await self.get(str(record_to_save["approval_id"])) or record_to_save

    async def _get_raw(self, approval_id: str) -> Optional[Dict[str, Any]]:
        """رکورد را بدون اعمال expiry می‌خواند؛ helper داخلی برای جلوگیری از recursion است."""
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
        """TTL را با زمان UTC محاسبه می‌کند تا timezone محلی روی مجوز اثر نگذارد."""
        created_at = record.get("created_at")
        if created_at is None or settings.APPROVAL_TTL_SECONDS <= 0:
            return False
        if isinstance(created_at, str):
            created_at = datetime.fromisoformat(created_at.replace("Z", "+00:00"))
        if created_at.tzinfo is None:
            created_at = created_at.replace(tzinfo=timezone.utc)
        return (datetime.now(timezone.utc) - created_at.astimezone(timezone.utc)).total_seconds() > settings.APPROVAL_TTL_SECONDS

    async def get(self, approval_id: str) -> Optional[Dict[str, Any]]:
        """رکورد را می‌خواند و Approval منقضی را قبل از استفاده به expired تبدیل می‌کند."""
        record = await self._get_raw(approval_id)
        if record and record.get("status") in {"pending", "approved"} and self._expired(record):
            # Expiry فقط در حافظه محاسبه نمی‌شود؛ persisted شدن آن باعث می‌شود worker
            # دیگری هم همان approval را معتبر فرض نکند.
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
        """فقط یک Approval هنوز-pending را اتمیک به approved یا rejected transition می‌دهد."""
        if status not in {"approved", "rejected"}:
            raise ValueError("invalid_approval_status")

        # قبل از transition، get() ممکن است رکورد را expired کند. در نتیجه approval
        # منقضی هیچ‌وقت از مسیر status update به approved برنمی‌گردد.
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
        # شرط status='pending' خود PostgreSQL race دو approver همزمان را حل می‌کند؛
        # loser فقط وضعیت نهایی را می‌خواند و caller باید conflict را گزارش کند.
        return dict(row) if row else await self._get_raw(approval_id)

    async def cancel_unconsumed_for_incident(
        self,
        incident_id: str,
        *,
        reason: str,
        metadata_patch: Optional[Dict[str, Any]] = None,
    ) -> list[str]:
        """Invalidate pending/approved authority after recovery or another terminal fact."""
        patch = {"cancellation_reason": reason, **dict(metadata_patch or {})}
        rows = (
            await self.session.execute(
                text(
                    """
                    UPDATE approvals
                    SET status='rejected',
                        rejected_at=CURRENT_TIMESTAMP,
                        metadata=COALESCE(metadata, '{}'::jsonb) || CAST(:metadata_patch AS jsonb)
                    WHERE incident_id=:incident_id
                      AND status IN ('pending', 'approved')
                    RETURNING approval_id
                    """
                ),
                {
                    "incident_id": incident_id,
                    "metadata_patch": json.dumps(patch, default=str),
                },
            )
        ).scalars().all()
        await self.session.commit()
        return [str(value) for value in rows]

    async def consume(self, approval_id: str) -> Optional[Dict[str, Any]]:
        """Approval approved را دقیقاً یک بار درست قبل از عبور از execution boundary مصرف می‌کند."""
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
        # Atomic compare-and-set مانع replay همان approval برای execution دوم می‌شود.
        return dict(row) if row else await self._get_raw(approval_id)

    async def is_approved(self, approval_id: str) -> bool:
        """برای read-only check؛ execution واقعی همچنان باید consume اتمیک انجام دهد."""
        record = await self.get(approval_id)
        return bool(record and record.get("status") == "approved")
