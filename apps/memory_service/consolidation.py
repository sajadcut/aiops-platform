from __future__ import annotations

from collections import Counter
from typing import Any, Dict, Iterable

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from domain.models import MemoryEntry


def summarize_entries(entries: Iterable[MemoryEntry]) -> Dict[str, Any]:
    rows = list(entries)
    outcomes = Counter(
        str(row.memory_outcome_class or "unknown")
        for row in rows
    )
    actions = Counter()
    causes = Counter()
    for row in rows:
        remediation = row.actual_remediation or {}
        action = str(remediation.get("action") or row.action or "").strip()
        if action:
            actions[action] += 1
        cause_key = str(row.root_cause_status or "unknown")
        causes[cause_key] += 1
    return {
        "occurrences": len(rows),
        "outcomes": dict(outcomes),
        "remediation_actions": dict(actions),
        "root_cause_statuses": dict(causes),
        "policy": (
            "Consolidated Operational Experience is historical context, "
            "not current Live Evidence."
        ),
    }


async def summarize_service(
    db: AsyncSession,
    service_scope: str,
    *,
    limit: int = 500,
) -> Dict[str, Any]:
    rows = (
        await db.execute(
            select(MemoryEntry)
            .where(
                MemoryEntry.service_scope == service_scope,
                MemoryEntry.lifecycle_status == "active",
            )
            .order_by(MemoryEntry.created_at.desc())
            .limit(max(1, min(int(limit), 2000)))
        )
    ).scalars().all()
    result = summarize_entries(rows)
    result["service_scope"] = service_scope
    return result
