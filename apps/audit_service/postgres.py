from __future__ import annotations

import json
from typing import Any, Dict, List, Optional
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession


class PostgreSQLAuditStore:
    """Durable audit persistence adapter for the MASTER audit contract."""

    def __init__(self, session: AsyncSession):
        self.session = session

    async def append(self, event: Dict[str, Any]) -> Dict[str, Any]:
        params = dict(event)
        params["metadata"] = json.dumps(event.get("metadata") or {}, default=str)
        await self.session.execute(
            text(
                """INSERT INTO audit_events
                (event_id, event_type, actor, incident_id, action, status, metadata, created_at)
                VALUES (:event_id, :event_type, :actor, :incident_id, :action,
                        :status, CAST(:metadata AS jsonb), :created_at)"""
            ),
            params,
        )
        await self.session.commit()
        return event

    async def list(self, incident_id: Optional[str] = None, limit: int = 100) -> List[Dict[str, Any]]:
        if incident_id:
            stmt = text(
                "SELECT event_id,event_type,actor,incident_id,action,status,metadata,created_at "
                "FROM audit_events WHERE incident_id=:incident_id ORDER BY created_at DESC LIMIT :limit"
            )
            params = {"incident_id": incident_id, "limit": limit}
        else:
            stmt = text(
                "SELECT event_id,event_type,actor,incident_id,action,status,metadata,created_at "
                "FROM audit_events ORDER BY created_at DESC LIMIT :limit"
            )
            params = {"limit": limit}
        rows = (await self.session.execute(stmt, params)).mappings().all()
        return [dict(row) for row in rows]
