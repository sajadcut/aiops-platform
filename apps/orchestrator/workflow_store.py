from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession


class WorkflowCheckpointStore:
    """Durable checkpoint store for incident workflow state.

    The store keeps the latest resumable state per incident and a monotonically
    increasing version. It is intentionally storage-only; LangGraph remains
    responsible for graph semantics while this store provides restart/resume
    durability for the application layer.
    """

    def __init__(self, session: AsyncSession):
        self.session = session

    async def save(self, incident_id: str, state: Dict[str, Any], status: str = "paused") -> Dict[str, Any]:
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
        await self.session.commit()
        return {"incident_id": incident_id, "status": status, "updated_at": now.isoformat()}

    async def load(self, incident_id: str) -> Optional[Dict[str, Any]]:
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
        return await self.save(incident_id, state, status="completed")

    async def mark_failed(self, incident_id: str, state: Dict[str, Any]) -> Dict[str, Any]:
        return await self.save(incident_id, state, status="failed")
