from __future__ import annotations

import contextvars
from hashlib import blake2s
from typing import Any
from uuid import UUID, uuid4

# Request/incident correlation is kept in ContextVar so concurrent asyncio
# tasks do not leak identifiers into one another.
_trace_id: contextvars.ContextVar[str] = contextvars.ContextVar("trace_id", default="")
_incident_id: contextvars.ContextVar[str] = contextvars.ContextVar("incident_id", default="")
_rid: contextvars.ContextVar[str] = contextvars.ContextVar("rid", default="")


def set_trace_id(trace_id: str) -> None:
    """Set the request/correlation trace id for the current execution context."""
    _trace_id.set(str(trace_id or ""))


def get_trace_id() -> str:
    """Return the request/correlation trace id for the current context."""
    return _trace_id.get()


def generate_trace_id() -> str:
    """Generate a compact request trace id."""
    return f"trc_{uuid4().hex[:12]}"


def incident_rid(incident_id: Any) -> str:
    """Return a stable RID for an Incident without requiring a database column.

    Incident IDs are UUIDs in production. Their canonical 32-hex representation
    is collision-free with respect to the Incident primary key. Non-UUID values
    are accepted for tests/legacy callers and mapped to a deterministic BLAKE2s
    digest so raw arbitrary input is never copied into the RID.
    """
    raw = str(incident_id or "").strip()
    if not raw:
        return ""
    try:
        token = UUID(raw).hex
    except (TypeError, ValueError, AttributeError):
        token = blake2s(raw.encode("utf-8"), digest_size=16).hexdigest()
    return f"rid_{token}"


def bind_incident_context(incident_id: Any) -> str:
    """Bind Incident identity and its stable RID to the current async context."""
    raw = str(incident_id or "").strip()
    if not raw:
        clear_incident_context()
        return ""
    rid = incident_rid(raw)
    _incident_id.set(raw)
    _rid.set(rid)
    return rid


def clear_incident_context() -> None:
    """Clear Incident correlation fields from the current execution context."""
    _incident_id.set("")
    _rid.set("")


def get_incident_id() -> str:
    """Return the bound Incident id, if any."""
    return _incident_id.get()


def get_rid() -> str:
    """Return the bound Incident RID, if any."""
    return _rid.get()
