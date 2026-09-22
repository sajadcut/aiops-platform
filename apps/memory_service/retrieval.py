from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy import and_, desc, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from domain.contracts.config import settings
from domain.contracts.logging import logger
from domain.models import MemoryEntry
from knowledge import EmbeddingService


SUCCESS_STATUSES = {"success", "succeeded", "verified"}
MODES = {"SIMILAR_INCIDENT", "RCA_ANALOG", "REMEDIATION_EXPERIENCE"}


async def candidates(
    db: AsyncSession,
    query: str,
    *,
    service_scope: Optional[str],
    environment: Optional[str],
    mode: str,
    limit: int,
    successful_only: bool,
) -> List[Dict[str, Any]]:
    mode = str(mode or "SIMILAR_INCIDENT").upper()
    if mode not in MODES:
        raise ValueError("unsupported_memory_retrieval_mode")

    conditions = [
        MemoryEntry.lifecycle_status == "active",
        MemoryEntry.outcome.is_not(None),
    ]
    if service_scope:
        conditions.append(MemoryEntry.service_scope == service_scope)
    if environment:
        conditions.append(
            or_(
                MemoryEntry.environment == environment,
                MemoryEntry.environment.is_(None),
            )
        )
    if successful_only:
        conditions.append(
            MemoryEntry.verification_result.in_(sorted(SUCCESS_STATUSES))
        )
    if mode == "REMEDIATION_EXPERIENCE":
        conditions.append(
            MemoryEntry.memory_outcome_class.in_(
                [
                    "successful_recovery",
                    "failed_recovery",
                    "partial_recovery",
                    "execution_blocked",
                ]
            )
        )

    multiplier = max(
        2,
        int(getattr(settings, "MEMORY_RETRIEVAL_CANDIDATE_MULTIPLIER", 4)),
    )
    cap = min(200, max(1, limit) * multiplier)
    vector_rows: List[Tuple[MemoryEntry, float]] = []
    lexical_rows: List[Tuple[MemoryEntry, float]] = []

    try:
        vector = await EmbeddingService.generate_embedding(query)
        distance = MemoryEntry.embedding.cosine_distance(vector).label("distance")
        stmt = (
            select(MemoryEntry, distance)
            .where(and_(*conditions, MemoryEntry.embedding.is_not(None)))
            .order_by(distance)
            .limit(cap)
        )
        vector_rows = [
            (row[0], float(row[1]))
            for row in (await db.execute(stmt)).all()
        ]
    except Exception as exc:
        logger.warning(
            "operational_memory_vector_retrieval_degraded",
            error_type=type(exc).__name__,
        )
        await db.rollback()

    if bool(getattr(settings, "MEMORY_HYBRID_RETRIEVAL_ENABLED", True)):
        try:
            document = func.to_tsvector(
                "simple",
                func.coalesce(
                    MemoryEntry.search_document,
                    MemoryEntry.pattern,
                    "",
                ),
            )
            tsquery = func.plainto_tsquery("simple", query)
            score = func.ts_rank_cd(document, tsquery).label("lexical_score")
            stmt = (
                select(MemoryEntry, score)
                .where(and_(*conditions, document.op("@@")(tsquery)))
                .order_by(desc(score))
                .limit(cap)
            )
            lexical_rows = [
                (row[0], float(row[1] or 0.0))
                for row in (await db.execute(stmt)).all()
            ]
        except Exception as exc:
            logger.warning(
                "operational_memory_lexical_retrieval_degraded",
                error_type=type(exc).__name__,
            )
            await db.rollback()

    merged: Dict[str, Dict[str, Any]] = {}
    for rank, (entry, distance) in enumerate(vector_rows, 1):
        item = merged.setdefault(str(entry.id), {"entry": entry})
        item["vector_rank"] = rank
        item["vector_similarity"] = max(0.0, min(1.0, 1.0 - distance))
    for rank, (entry, lexical) in enumerate(lexical_rows, 1):
        item = merged.setdefault(str(entry.id), {"entry": entry})
        item["lexical_rank"] = rank
        item["lexical_score"] = lexical
    return list(merged.values())


def rrf_score(
    item: Dict[str, Any],
    *,
    service_scope: Optional[str],
    environment: Optional[str],
    mode: str,
) -> float:
    entry = item["entry"]
    k = max(1, int(getattr(settings, "MEMORY_RRF_K", 60)))
    score = 0.0
    if item.get("vector_rank"):
        score += 1.0 / (k + int(item["vector_rank"]))
    if item.get("lexical_rank"):
        score += 1.0 / (k + int(item["lexical_rank"]))
    if service_scope and entry.service_scope == service_scope:
        score += 0.03
    if environment and entry.environment == environment:
        score += 0.01
    if entry.verification_result in SUCCESS_STATUSES:
        score += 0.01
    if (
        mode == "REMEDIATION_EXPERIENCE"
        and entry.memory_outcome_class == "failed_recovery"
    ):
        score += 0.008
    score += min(
        0.02,
        max(0.0, float(entry.effectiveness_score or 0.0)) * 0.02,
    )
    return score
