from __future__ import annotations

import argparse
import asyncio
import json
from typing import Any

from sqlalchemy import desc, select

from apps.memory_service import OperationalMemoryService
from database import AsyncSessionLocal
from database.migration_validation import validate_migration_head
from domain.models import MemoryEntry


async def inspect(limit: int) -> dict[str, Any]:
    async with AsyncSessionLocal() as db:
        migration = await validate_migration_head(db)
        service = OperationalMemoryService(db)
        stats = await service.stats()
        rows = (
            await db.execute(
                select(MemoryEntry)
                .order_by(desc(MemoryEntry.created_at))
                .limit(max(1, min(int(limit), 100)))
            )
        ).scalars().all()

    latest = [
        {
            "id": str(row.id),
            "incident_id": str(row.incident_id) if row.incident_id else None,
            "service_scope": row.service_scope,
            "verification_result": row.verification_result,
            "memory_outcome_class": row.memory_outcome_class,
            "lifecycle_status": row.lifecycle_status,
            "embedding_status": row.embedding_status,
            "embedding_provider": row.embedding_provider,
            "embedding_model": row.embedding_model,
            "created_at": row.created_at.isoformat() if row.created_at else None,
        }
        for row in rows
    ]
    return {
        "migration": migration,
        "stats": stats,
        "latest": latest,
    }


async def main(limit: int, require_entry: bool) -> int:
    payload = await inspect(limit)
    print(json.dumps(payload, ensure_ascii=False, indent=2, default=str))

    migration = payload.get("migration") or {}
    if not migration.get("valid"):
        return 2
    if require_entry and int((payload.get("stats") or {}).get("entries_total") or 0) <= 0:
        return 3
    return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description=(
            "Verify Operational Memory persistence, migration state and "
            "embedding/lifecycle health without exposing stored secrets."
        )
    )
    parser.add_argument("--limit", type=int, default=10)
    parser.add_argument(
        "--require-entry",
        action="store_true",
        help="exit non-zero when memory_entries is still empty",
    )
    args = parser.parse_args()
    raise SystemExit(asyncio.run(main(args.limit, args.require_entry)))
