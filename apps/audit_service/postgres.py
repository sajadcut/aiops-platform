from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession


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
            raise ValueError("invalid_audit_timestamp") from exc
    else:
        return value
    if parsed is not None and parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


class PostgreSQLAuditStore:
    """Durable audit persistence adapter for the MASTER audit contract."""

    def __init__(self, session: AsyncSession):
        self.session = session

    async def append(self, event: Dict[str, Any]) -> Dict[str, Any]:
        params = dict(event)
        params["metadata"] = json.dumps(event.get("metadata") or {}, default=str)
        # AuditService keeps its public/domain events JSON-friendly by storing
        # created_at as an ISO string. PostgreSQL uses TIMESTAMPTZ, and asyncpg
        # requires a native datetime for that bind parameter.
        params["created_at"] = _db_timestamp(params.get("created_at"))
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
