from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, Iterable, Optional
from uuid import UUID, uuid4

from sqlalchemy import and_, select
from sqlalchemy.ext.asyncio import AsyncSession

from domain.contracts.config import settings
from domain.contracts.logging import logger
from domain.models import MemoryEntry, MemoryReuseEvent
from .telemetry import MEMORY_FEEDBACK_TOTAL


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
    cited_memory_ids: Optional[Iterable[str]] = None,
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
    cited = {str(value) for value in (cited_memory_ids or []) if str(value).strip()}
    now = datetime.now(timezone.utc)
    rewarded_memory_ids: set[UUID] = set()
    cited_memory_ids_seen: set[UUID] = set()

    for event in events:
        action_matches = bool(current_action and event.suggested_action == current_action)
        explicitly_cited = str(event.memory_id) in cited
        influenced = bool(action_matches and explicitly_cited)
        event.action_executed = action_matches
        event.was_cited_by_agent = explicitly_cited
        event.influenced_plan = influenced
        event.verification_result = status
        if influenced and status in {"success", "succeeded", "verified"}:
            event.helpful = True
            event.reward_score = 1.0
        elif influenced and status in {"failed", "failure"}:
            event.helpful = False
            event.reward_score = -1.0
        elif influenced and status == "partial":
            event.reward_score = 0.25
        else:
            event.helpful = None
            event.reward_score = 0.0

        attribution = (
            "cited_and_matched"
            if influenced
            else "cited_action_mismatch"
            if explicitly_cited
            else "not_cited"
        )
        MEMORY_FEEDBACK_TOTAL.labels(
            verification_status=status,
            attribution=attribution,
        ).inc()

        entry = await db.get(MemoryEntry, event.memory_id)
        if entry is None:
            continue

        if explicitly_cited and event.memory_id not in cited_memory_ids_seen:
            cited_memory_ids_seen.add(event.memory_id)
            entry.cited_count = int(entry.cited_count or 0) + 1

        if not influenced or event.memory_id in rewarded_memory_ids:
            continue

        rewarded_memory_ids.add(event.memory_id)
        entry.reuse_count = int(entry.reuse_count or 0) + 1
        entry.last_reused_at = now
        if status in {"success", "succeeded", "verified"}:
            entry.successful_reuse_count = int(entry.successful_reuse_count or 0) + 1
            entry.last_successful_reuse_at = now
        elif status in {"failed", "failure"}:
            entry.failed_reuse_count = int(entry.failed_reuse_count or 0) + 1
        attempts = int(entry.successful_reuse_count or 0) + int(entry.failed_reuse_count or 0)
        entry.effectiveness_score = (
            float(entry.successful_reuse_count or 0) / attempts if attempts else 0.0
        )
        logger.info(
            "aiops.memory.reused",
            memory_id=str(event.memory_id),
            target_incident_id=target_incident_id,
            service_name=entry.service_scope,
            environment=entry.environment,
            retrieval_mode=event.retrieval_mode,
            rank_position=event.rank_position,
            verification_status=status,
            helpful=event.helpful,
            reward_score=float(event.reward_score or 0.0),
        )

    await db.commit()
    logger.info(
        "aiops.memory.feedback.recorded",
        target_incident_id=target_incident_id,
        count=len(events),
        cited_memory_count=len(cited_memory_ids_seen),
        attributed_memory_count=len(rewarded_memory_ids),
        verification_status=status,
    )
    return len(events)
