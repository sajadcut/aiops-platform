from __future__ import annotations

from typing import Any, Dict, Iterable, Optional
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession


async def record_retrieval_events(
    db: AsyncSession,
    items: Iterable[Dict[str, Any]],
    *,
    target_incident_id: str,
    retrieval_mode: str,
) -> None:
    """Hook for durable retrieval telemetry; persistence is added by migration-backed deployments."""
    return None


async def apply_feedback(
    db: AsyncSession,
    target_incident_id: str,
    *,
    execution_request: Optional[Dict[str, Any]],
    verification_result: Optional[Dict[str, Any]],
) -> int:
    """Return the number of historical-memory reuse records updated."""
    return 0
