"""Operational audit trail service with durable flush support."""

from __future__ import annotations

from dataclasses import asdict, dataclass
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
    def list_events(cls, incident_id: Optional[str] = None, limit: int = 100) -> List[Dict[str, Any]]:
        events = cls._events
        if incident_id:
            events = [e for e in events if e.incident_id == incident_id]
        return [asdict(e) for e in events[-max(1, limit):]]

    @classmethod
    async def flush_to_store(cls, store: Any, incident_id: Optional[str] = None) -> int:
        """Persist buffered events through an injected durable store."""
        pending = cls.list_events(incident_id=incident_id, limit=max(len(cls._events), 1))
        for event in pending:
            await store.append(event)
        if incident_id:
            cls._events = [e for e in cls._events if e.incident_id != incident_id]
        else:
            cls._events.clear()
        return len(pending)

    @classmethod
    def clear(cls) -> None:
        cls._events.clear()
