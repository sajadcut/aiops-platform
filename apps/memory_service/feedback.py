from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, Iterable, Optional
from uuid import UUID, uuid4

from sqlalchemy import and_, select
from sqlalchemy.ext.asyncio import AsyncSession

from domain.contracts.config import settings
from domain.contracts.logging import logger
from domain.models import MemoryEntry, MemoryReuseEvent


def _uuid(value: Any) -> Optional[UUID]:
    if isinstance(value, UUID):
        return value
    if not value:
        return None
    try:
        return UUID(str(value))
    except (TypeError, ValueError):
        return None


async def record_retrieval_events(
    db: AsyncSession,
    items: Iterable[Dict[str, Any]],
    *,
    target_incident_id: str,
    retrieval_mode: str,
) -> None:
    target = _uuid(target_incident_id)
    if target is None:
        return
    now = datetime.now(timezone.utc)
    for item in items:
        memory_id = _uuid(item.get("id"))
        if memory_id is None:
            continue
        prior = item.get("actual_remediation") or {}
        db.add(
            MemoryReuseEvent(
                id=uuid4(),
                memory_id=memory_id,
                target_incident_id=target,
                retrieved_at=now,
                retrieval_mode=retrieval_mode,
                vector_similarity=float(item.get("vector_similarity") or 0),
                lexical_score=float(item.get("lexical_score") or 0),
                final_rank_score=float(item.get("final_rank_score") or 0),
                rank_position=int(item.get("rank_position") or 0),
                was_presented_to_agent=True,
                suggested_action=prior.get("action"),
            )
        )
        entry = await db.get(MemoryEntry, memory_id)
        if entry is not None:
            entry.retrieval_count = int(entry.retrieval_count or 0) + 1
            entry.last_retrieved_at = now
    await db.commit()


async def apply_feedback(
    db: AsyncSession,
    target_incident_id: str,
    *,
    execution_request: Optional[Dict[str, Any]],
    verification_result: Optional[Dict[str, Any]],
) -> int:
    if not bool(getattr(settings, "MEMORY_REUSE_FEEDBACK_ENABLED", True)):
        return 0
    target = _uuid(target_incident_id)
    if target is None:
        return 0

    events = (
        await db.execute(
            select(MemoryReuseEvent).where(
                and_(
                    MemoryReuseEvent.target_incident_id == target,
                    MemoryReuseEvent.verification_result.is_(None),
                )
            )
        )
    ).scalars().all()
    current_action = str((execution_request or {}).get("action") or "").strip()
    status = str((verification_result or {}).get("status") or "inconclusive").lower()
    now = datetime.now(timezone.utc)

    for event in events:
        reused = bool(current_action and event.suggested_action == current_action)
        event.action_executed = reused
        event.influenced_plan = reused
        event.verification_result = status
        if reused and status == "success":
            event.helpful = True
            event.reward_score = 1.0
        elif reused and status in {"failed", "failure"}:
            event.helpful = False
            event.reward_score = -1.0
        elif reused and status == "partial":
            event.reward_score = 0.25

        entry = await db.get(MemoryEntry, event.memory_id)
        if entry is None or not reused:
            continue
        entry.reuse_count = int(entry.reuse_count or 0) + 1
        entry.last_reused_at = now
        if status == "success":
            entry.successful_reuse_count = int(entry.successful_reuse_count or 0) + 1
            entry.last_successful_reuse_at = now
        elif status in {"failed", "failure"}:
            entry.failed_reuse_count = int(entry.failed_reuse_count or 0) + 1
        attempts = int(entry.successful_reuse_count or 0) + int(entry.failed_reuse_count or 0)
        entry.effectiveness_score = (
            float(entry.successful_reuse_count or 0) / attempts if attempts else 0.0
        )

    await db.commit()
    logger.info(
        "aiops.memory.feedback.recorded",
        target_incident_id=target_incident_id,
        count=len(events),
        verification_status=status,
    )
    return len(events)
