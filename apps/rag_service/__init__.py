from datetime import datetime, timezone
from typing import List, Optional, Dict, Any
from uuid import UUID, uuid4

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from domain.models import KnowledgeDocument
from knowledge import EmbeddingService
from knowledge.retrieval_contract import validate_retrieval
from domain.contracts.config import settings
from domain.contracts.logging import logger


class KnowledgeRAGService:
    """Governed Knowledge RAG backed by PostgreSQL + pgvector."""

    def __init__(self, db: AsyncSession):
        self.db = db

    @staticmethod
    def _govern_metadata(metadata: Dict[str, Any], version: Optional[str]) -> Dict[str, Any]:
        governed = dict(metadata)
        governed.setdefault("namespace", "knowledge")
        governed.setdefault("acl", ["internal"])
        source_type = str(governed.get("source_type") or "").strip().lower()
        owner = str(governed.get("owner") or "").strip()
        if settings.APP_ENV == "production" and settings.KNOWLEDGE_REQUIRE_GOVERNANCE_PRODUCTION:
            if source_type not in settings.KNOWLEDGE_ALLOWED_SOURCE_TYPES:
                raise ValueError("knowledge_source_type_not_allowlisted")
            if not owner:
                raise ValueError("knowledge_owner_required")
            if not version:
                raise ValueError("knowledge_version_required")
        if source_type and source_type not in settings.KNOWLEDGE_ALLOWED_SOURCE_TYPES:
            raise ValueError("knowledge_source_type_not_allowlisted")
        return governed

    async def add_document(
        self,
        title: str,
        content: str,
        source: str,
        version: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> UUID:
        if not title.strip() or not content.strip() or not source.strip():
            raise ValueError("knowledge_title_content_source_required")
        extra_metadata = self._govern_metadata(dict(metadata or {}), version)
        embedding = await EmbeddingService.generate_embedding(content)
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
        logger.info(f"Added governed knowledge document: {title} (ID: {doc.id})")
        return doc.id

    @staticmethod
    def _acl_allowed(metadata: Dict[str, Any], access_scopes: List[str]) -> bool:
        acl = metadata.get("acl") or ["internal"]
        if isinstance(acl, str):
            acl = [acl]
        return bool(set(str(v) for v in acl) & set(access_scopes)) or "public" in acl

    async def search(
        self,
        query: str,
        limit: int = 5,
        min_similarity: float = 0.5,
        access_scopes: Optional[List[str]] = None,
    ) -> List[Dict[str, Any]]:
        if not query.strip():
            return []
        scopes = access_scopes or ["internal"]
        query_embedding = await EmbeddingService.generate_embedding(query)
        stmt = (
            select(
                KnowledgeDocument,
                KnowledgeDocument.embedding.cosine_distance(query_embedding).label("distance"),
            )
            .where(KnowledgeDocument.embedding.is_not(None))
            .order_by("distance")
            .limit(max(limit * 3, limit))
        )
        result = await self.db.execute(stmt)
        rows = result.all()
        retrieved_at = datetime.now(timezone.utc).isoformat()
        documents: List[Dict[str, Any]] = []

        for row in rows:
            doc = row[0]
            metadata = dict(doc.extra_metadata or {})
            if metadata.get("namespace", "knowledge") != "knowledge":
                continue
            if not self._acl_allowed(metadata, scopes):
                continue
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
                "source_type": metadata.get("source_type"),
                "owner": metadata.get("owner"),
                "acl": metadata.get("acl", ["internal"]),
                "version": doc.version,
                "extra_metadata": metadata,
                "similarity": similarity,
                "relevance": similarity,
                "retrieved_at": retrieved_at,
            }
            if not validate_retrieval(item):
                raise ValueError(f"Invalid RAG retrieval contract for document {doc.id}")
            documents.append(item)
            if len(documents) >= limit:
                break

        logger.info(f"Governed RAG search returned {len(documents)} documents")
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
                "created_at": doc.created_at.isoformat() if doc.created_at else None,
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
