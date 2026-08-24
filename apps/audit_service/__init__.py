"""Operational audit trail service.

The service keeps a normalized audit contract independent from the transport
layer. Persistence is intentionally injectable so PostgreSQL storage can be
added without changing callers.
"""

from __future__ import annotations

from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from uuid import uuid4


@dataclass(frozen=True)
class AuditEvent:
    event_id: str
    event_type: str
    actor: str
    incident_id: Optional[str]
    action: Optional[str]
    status: str
    metadata: Dict[str, Any]
    created_at: str


class AuditService:
    _events: List[AuditEvent] = []

    @classmethod
    def record(
        cls,
        event_type: str,
        actor: str,
        incident_id: Optional[str] = None,
        action: Optional[str] = None,
        status: str = "recorded",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> AuditEvent:
        event = AuditEvent(
            event_id=str(uuid4()),
            event_type=event_type,
            actor=actor,
            incident_id=incident_id,
            action=action,
            status=status,
            metadata=metadata or {},
            created_at=datetime.now(timezone.utc).isoformat(),
        )
        cls._events.append(event)
        return event

    @classmethod
    def list_events(
        cls,
        incident_id: Optional[str] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        events = cls._events
        if incident_id:
            events = [e for e in events if e.incident_id == incident_id]
        return [asdict(e) for e in events[-max(1, limit):]]

    @classmethod
    def clear(cls) -> None:
        cls._events.clear()
