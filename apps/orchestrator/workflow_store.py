"""Persistence لایه LangGraph checkpoint.

این فایل semantics گراف را تعیین نمی‌کند؛ فقط آخرین state قابل resume هر Incident را
به‌صورت durable در PostgreSQL نگه می‌دارد. جدا بودن این مسئولیت مهم است چون crash یا
restart نباید باعث شروع دوباره remediation از ابتدا یا تکرار action حساس شود.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession


class WorkflowCheckpointStore:
    """State قابل resume را با version افزایشی برای هر Incident ذخیره می‌کند."""

    def __init__(self, session: AsyncSession):
        self.session = session

    async def save(self, incident_id: str, state: Dict[str, Any], status: str = "paused") -> Dict[str, Any]:
        # state ممکن است UUID/datetime/Pydantic object داشته باشد. این round-trip آن را
        # قبل از JSONB persistence به ساختار JSON-safe تبدیل می‌کند بدون تغییر graph logic.
        payload = json.loads(json.dumps(state, default=str))
        now = datetime.now(timezone.utc)
        await self.session.execute(
            text(
                """
                INSERT INTO workflow_checkpoints (incident_id, state, status, version, updated_at)
                VALUES (:incident_id, CAST(:state AS jsonb), :status, 1, :updated_at)
                ON CONFLICT (incident_id)
                DO UPDATE SET state=EXCLUDED.state,
                              status=EXCLUDED.status,
                              version=workflow_checkpoints.version + 1,
                              updated_at=EXCLUDED.updated_at
                """
            ),
            {"incident_id": incident_id, "state": json.dumps(payload), "status": status, "updated_at": now},
        )
        # commit در همین store انجام می‌شود تا pause/approval checkpoint واقعاً durable باشد
        # و API قبل از crash یک state فقط در حافظه گزارش نکند.
        await self.session.commit()
        return {"incident_id": incident_id, "status": status, "updated_at": now.isoformat()}

    async def load(self, incident_id: str) -> Optional[Dict[str, Any]]:
        """آخرین state/version یک Incident را برای resume یا Dashboard برمی‌گرداند."""
        row = (
            await self.session.execute(
                text("SELECT incident_id, state, status, version, updated_at FROM workflow_checkpoints WHERE incident_id=:id"),
                {"id": incident_id},
            )
        ).mappings().first()
        if not row:
            return None
        data = dict(row)
        if isinstance(data.get("state"), str):
            data["state"] = json.loads(data["state"])
        return data

    async def mark_completed(self, incident_id: str, state: Dict[str, Any]) -> Dict[str, Any]:
        """Terminal success را با همان state نهایی durable می‌کند."""
        return await self.save(incident_id, state, status="completed")

    async def mark_failed(self, incident_id: str, state: Dict[str, Any]) -> Dict[str, Any]:
        """Terminal failure را نگه می‌دارد تا علت شکست بعد از restart قابل audit باشد."""
        return await self.save(incident_id, state, status="failed")
