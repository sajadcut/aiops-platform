from __future__ import annotations

from typing import Any, Dict, List, Optional, cast
from uuid import UUID, uuid4

from sqlalchemy import and_, select
from sqlalchemy.ext.asyncio import AsyncSession

from domain.contracts.logging import logger
from domain.models import MemoryEntry
from knowledge import EmbeddingService


class OperationalMemoryService:
    """Operational Memory backed by PostgreSQL + pgvector.

    Knowledge RAG and Operational Memory remain logically isolated through an
    explicit namespace and metadata contract.
    """

    NAMESPACE = "operational_memory"

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
        metadata: Optional[Dict[str, Any]] = None,
    ) -> UUID:
        embedding = await EmbeddingService.generate_embedding(pattern)
        extra_metadata = dict(metadata or {})
        extra_metadata["namespace"] = self.NAMESPACE
        extra_metadata.setdefault("source_type", "incident_outcome")
        if incident_id:
            extra_metadata.setdefault("source_reference", str(incident_id))

        entry = MemoryEntry(
            id=uuid4(),
            incident_id=incident_id,
            pattern=pattern,
            symptoms=symptoms,
            root_cause=root_cause,
            action=action,
            verification_result=verification_result,
            outcome=outcome,
            environment=environment,
            service_scope=service_scope,
            extra_metadata=extra_metadata,
            embedding=embedding,
            reuse_count=0,
        )
        self.db.add(entry)
        await self.db.commit()
        await self.db.refresh(entry)
        logger.info(f"Added operational memory entry {entry.id}")
        return cast(UUID, entry.id)

    async def search_similar(
        self,
        query: str,
        service_scope: Optional[str] = None,
        limit: int = 5,
        min_similarity: float = 0.0,
    ) -> List[Dict[str, Any]]:
        query_embedding = await EmbeddingService.generate_embedding(query)
        conditions = [MemoryEntry.embedding.is_not(None)]
        if service_scope:
            conditions.append(MemoryEntry.service_scope == service_scope)
        conditions.append(
            MemoryEntry.extra_metadata["namespace"].astext == self.NAMESPACE
        )

        stmt = (
            select(
                MemoryEntry,
                MemoryEntry.embedding.cosine_distance(query_embedding).label("distance"),
            )
            .where(and_(*conditions))
            .order_by("distance")
            .limit(max(1, min(limit, 50)))
        )
        rows = (await self.db.execute(stmt)).all()

        entries: List[Dict[str, Any]] = []
        for row in rows:
            entry = row[0]
            similarity = max(0.0, min(1.0, 1.0 - float(row[1])))
            if similarity < min_similarity:
                continue
            entries.append(
                {
                    "id": str(entry.id),
                    "pattern": entry.pattern,
                    "symptoms": entry.symptoms,
                    "root_cause": entry.root_cause,
                    "action": entry.action,
                    "verification_result": entry.verification_result,
                    "outcome": entry.outcome,
                    "service_scope": entry.service_scope,
                    "extra_metadata": entry.extra_metadata,
                    "source_reference": (entry.extra_metadata or {}).get("source_reference"),
                    "namespace": self.NAMESPACE,
                    "reuse_count": entry.reuse_count,
                    "similarity": similarity,
                }
            )

        logger.info(f"Operational memory search returned {len(entries)} entries")
        return entries

    async def update_reuse_count(self, entry_id: UUID) -> None:
        entry = await self.db.get(MemoryEntry, entry_id)
        if entry:
            entry.reuse_count = int(entry.reuse_count or 0) + 1
            await self.db.commit()