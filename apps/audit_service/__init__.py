"""Operational audit trail service with durable flush support and secret redaction."""

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
    _SENSITIVE_KEYS = {
        "password", "passwd", "secret", "token", "access_token", "refresh_token",
        "authorization", "api_key", "apikey", "x_api_key", "private_key",
        "client_secret", "cookie", "set-cookie",
    }

    @classmethod
    def _redact(cls, value: Any, key: Optional[str] = None) -> Any:
        normalized = (key or "").lower().replace("-", "_")
        if normalized in cls._SENSITIVE_KEYS or any(term in normalized for term in ("password", "secret", "token", "api_key", "private_key")):
            return "[REDACTED]"
        if isinstance(value, dict):
            return {str(k): cls._redact(v, str(k)) for k, v in value.items()}
        if isinstance(value, list):
            return [cls._redact(item) for item in value]
        if isinstance(value, tuple):
            return tuple(cls._redact(item) for item in value)
        return value

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
            metadata=cls._redact(metadata or {}),
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
