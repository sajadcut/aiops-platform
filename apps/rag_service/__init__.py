from datetime import datetime, timezone
from typing import List, Optional, Dict, Any
from uuid import UUID, uuid4

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from domain.models import KnowledgeDocument
from knowledge import EmbeddingService
from knowledge.retrieval_contract import validate_retrieval
from domain.contracts.logging import logger


class KnowledgeRAGService:
    """Knowledge retrieval backed by PostgreSQL + pgvector."""

    def __init__(self, db: AsyncSession):
        self.db = db

    async def add_document(
        self,
        title: str,
        content: str,
        source: str,
        version: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> UUID:
        embedding = await EmbeddingService.generate_embedding(content)
        extra_metadata = dict(metadata or {})
        extra_metadata.setdefault("namespace", "knowledge")
        doc = KnowledgeDocument(
            id=uuid4(),
            title=title,
            content=content,
            source=source,
            version=version,
            extra_metadata=extra_metadata,
            embedding=embedding,
        )
        self.db.add(doc)
        await self.db.commit()
        await self.db.refresh(doc)
        logger.info(f"Added knowledge document: {title} (ID: {doc.id})")
        return doc.id

    async def search(
        self,
        query: str,
        limit: int = 5,
        min_similarity: float = 0.5,
    ) -> List[Dict[str, Any]]:
        query_embedding = await EmbeddingService.generate_embedding(query)
        stmt = (
            select(
                KnowledgeDocument,
                KnowledgeDocument.embedding.cosine_distance(query_embedding).label("distance"),
            )
            .where(KnowledgeDocument.embedding.is_not(None))
            .order_by("distance")
            .limit(limit)
        )
        result = await self.db.execute(stmt)
        rows = result.all()
        retrieved_at = datetime.now(timezone.utc).isoformat()
        documents: List[Dict[str, Any]] = []

        for row in rows:
            doc = row[0]
            distance = float(row[1])
            similarity = max(0.0, min(1.0, 1.0 - distance))
            if similarity < min_similarity:
                continue
            item = {
                "id": str(doc.id),
                "source_id": str(doc.id),
                "title": doc.title,
                "content": doc.content[:500] + "..." if len(doc.content) > 500 else doc.content,
                "source": doc.source,
                "version": doc.version,
                "extra_metadata": doc.extra_metadata,
                "similarity": similarity,
                "relevance": similarity,
                "retrieved_at": retrieved_at,
            }
            if not validate_retrieval(item):
                raise ValueError(f"Invalid RAG retrieval contract for document {doc.id}")
            documents.append(item)

        logger.info(f"RAG search returned {len(documents)} documents")
        return documents

    async def get_all_documents(self, limit: int = 100) -> List[Dict[str, Any]]:
        stmt = select(KnowledgeDocument).limit(limit)
        result = await self.db.execute(stmt)
        docs = result.scalars().all()
        return [
            {
                "id": str(doc.id),
                "source_id": str(doc.id),
                "title": doc.title,
                "content": doc.content[:200] + "..." if len(doc.content) > 200 else doc.content,
                "source": doc.source,
                "version": doc.version,
                "extra_metadata": doc.extra_metadata,
                "created_at": doc.created_at.isoformat(),
            }
            for doc in docs
        ]

    async def delete_document(self, doc_id: UUID) -> bool:
        stmt = select(KnowledgeDocument).where(KnowledgeDocument.id == doc_id)
        result = await self.db.execute(stmt)
        doc = result.scalar_one_or_none()
        if not doc:
            return False
        await self.db.delete(doc)
        await self.db.commit()
        logger.info(f"Deleted knowledge document: {doc_id}")
        return True
