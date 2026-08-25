from typing import List, Optional, Dict, Any, cast
from uuid import UUID, uuid4

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_

from domain.models import MemoryEntry
from knowledge import EmbeddingService
from domain.contracts.logging import logger


class OperationalMemoryService:
    """PostgreSQL + pgvector operational experience store, separate from Knowledge RAG."""

    SUCCESS_STATUSES = {"success", "succeeded", "verified"}
    VALID_STATUSES = SUCCESS_STATUSES | {"failed", "failure"}

    def __init__(self, db: AsyncSession):
        self.db = db

    async def add_entry(
        self,
        pattern: str,
        symptoms: Dict[str, Any],
        root_cause: Optional[str],
        action: Optional[str],
        verification_result: str,
        outcome: Optional[str],
        environment: Optional[str] = None,
        service_scope: Optional[str] = None,
        incident_id: Optional[UUID] = None,
    ) -> UUID:
        status = str(verification_result or "").strip().lower()
        if status not in self.VALID_STATUSES:
            raise ValueError("memory_requires_conclusive_verification")
        if not outcome or not str(outcome).strip():
            raise ValueError("memory_requires_outcome")
        if not pattern or not pattern.strip():
            raise ValueError("memory_requires_pattern")

        embedding = await EmbeddingService.generate_embedding(pattern)
        entry = MemoryEntry(
            id=uuid4(),
            incident_id=incident_id,
            pattern=pattern,
            symptoms=symptoms,
            root_cause=root_cause,
            action=action,
            verification_result=status,
            outcome=outcome,
            environment=environment,
            service_scope=service_scope,
            embedding=embedding,
            reuse_count=0,
        )
        self.db.add(entry)
        await self.db.commit()
        await self.db.refresh(entry)
        logger.info(f"Added verified memory entry: {pattern[:50]}... (ID: {entry.id})")
        return cast(UUID, entry.id)

    async def search_similar(
        self,
        query: str,
        service_scope: Optional[str] = None,
        limit: int = 5,
        min_similarity: float = 0.0,
        successful_only: bool = True,
    ) -> List[Dict[str, Any]]:
        if not query.strip():
            return []
        query_embedding = await EmbeddingService.generate_embedding(query)
        conditions = [MemoryEntry.embedding.is_not(None), MemoryEntry.outcome.is_not(None)]
        if service_scope:
            conditions.append(MemoryEntry.service_scope == service_scope)
        if successful_only:
            conditions.append(MemoryEntry.verification_result.in_(sorted(self.SUCCESS_STATUSES)))

        stmt = (
            select(
                MemoryEntry,
                MemoryEntry.embedding.cosine_distance(query_embedding).label("distance"),
            )
            .where(and_(*conditions))
            .order_by("distance")
            .limit(limit)
        )
        result = await self.db.execute(stmt)
        rows = result.all()
        entries: List[Dict[str, Any]] = []
        for row in rows:
            entry = row[0]
            similarity = max(0.0, min(1.0, 1.0 - float(row[1])))
            if similarity < min_similarity:
                continue
            entries.append({
                "id": str(entry.id),
                "source_incident_id": str(entry.incident_id) if entry.incident_id else None,
                "pattern": entry.pattern,
                "symptoms": entry.symptoms,
                "root_cause": entry.root_cause,
                "action": entry.action,
                "verification_result": entry.verification_result,
                "outcome": entry.outcome,
                "environment": entry.environment,
                "service_scope": entry.service_scope,
                "reuse_count": entry.reuse_count,
                "similarity": similarity,
                "created_at": entry.created_at.isoformat() if entry.created_at else None,
            })
        logger.info(f"Memory search returned {len(entries)} verified reusable entries")
        return entries

    async def update_reuse_count(self, entry_id: UUID) -> None:
        stmt = select(MemoryEntry).where(MemoryEntry.id == entry_id)
        result = await self.db.execute(stmt)
        entry = result.scalar_one_or_none()
        if entry:
            entry.reuse_count = int(entry.reuse_count or 0) + 1
            await self.db.commit()
            logger.info(f"Memory entry {entry_id} reuse count: {entry.reuse_count}")
