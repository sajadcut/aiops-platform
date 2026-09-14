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
from integrations.cognia import CogniaClient, CogniaContractError


class KnowledgeRAGService:
    """Provider-neutral governed Knowledge RAG boundary.

    Cognia is the canonical Governed Knowledge provider. ``local_pgvector`` is
    retained only for deterministic development/test and historical compatibility.
    Operational Memory remains an independent PostgreSQL + pgvector concern.
    """

    def __init__(self, db: Optional[AsyncSession]):
        self.db = db
        self.provider = settings.KNOWLEDGE_PROVIDER

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

    def _require_local_db(self) -> AsyncSession:
        if self.db is None:
            raise RuntimeError("local_pgvector_database_session_required")
        return self.db

    async def add_document(
        self,
        title: str,
        content: str,
        source: str,
        version: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> UUID:
        if self.provider != "local_pgvector":
            # Cognia registration requires an explicit KB, Scope, taxonomy and
            # Idempotency-Key. The old local method cannot safely infer them.
            raise RuntimeError("knowledge_authoring_must_use_cognia_governed_api")
        if not title.strip() or not content.strip() or not source.strip():
            raise ValueError("knowledge_title_content_source_required")
        db = self._require_local_db()
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
        db.add(doc)
        await db.commit()
        await db.refresh(doc)
        logger.info(f"Added governed local knowledge document: {title} (ID: {doc.id})")
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
        scope_context: Optional[Dict[str, Any]] = None,
    ) -> List[Dict[str, Any]]:
        if not query.strip():
            return []
        if limit <= 0:
            raise ValueError("knowledge_search_limit_must_be_positive")
        if not 0 <= min_similarity <= 1:
            raise ValueError("knowledge_min_relevance_must_be_between_0_and_1")
        if self.provider == "cognia":
            return await self._search_cognia(
                query,
                limit=limit,
                min_relevance=min_similarity,
                scope_context=scope_context,
            )
        return await self._search_local(
            query,
            limit=limit,
            min_similarity=min_similarity,
            access_scopes=access_scopes,
        )

    async def _search_cognia(
        self,
        query: str,
        *,
        limit: int,
        min_relevance: float,
        scope_context: Optional[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        retrieved_at = datetime.now(timezone.utc).isoformat()
        async with CogniaClient() as client:
            payload = await client.search(
                query,
                knowledge_base_ids=settings.COGNIA_KNOWLEDGE_BASE_IDS,
                limit=limit,
                scope_context=scope_context,
            )

        documents: List[Dict[str, Any]] = []
        for raw in payload.get("items", []):
            if not isinstance(raw, dict):
                raise CogniaContractError("cognia_search_item_must_be_object")
            required = (
                "knowledgeBaseId",
                "knowledgeId",
                "revisionId",
                "revisionNumber",
                "chunkId",
                "chunkText",
                "relevanceScore",
            )
            missing = [key for key in required if raw.get(key) is None]
            if missing:
                raise CogniaContractError("cognia_search_item_missing:" + ",".join(missing))
            try:
                relevance = float(raw["relevanceScore"])
            except (TypeError, ValueError) as exc:
                raise CogniaContractError("cognia_relevance_score_invalid") from exc
            if not 0 <= relevance <= 1:
                raise CogniaContractError("cognia_relevance_score_out_of_range")
            if relevance < min_relevance:
                continue

            knowledge_base_id = int(raw["knowledgeBaseId"])
            knowledge_id = int(raw["knowledgeId"])
            revision_id = int(raw["revisionId"])
            revision_number = int(raw["revisionNumber"])
            chunk_id = int(raw["chunkId"])
            source_id = (
                f"cognia:{knowledge_base_id}:{knowledge_id}:"
                f"{revision_id}:{chunk_id}"
            )
            item: Dict[str, Any] = {
                "id": source_id,
                "source_id": source_id,
                "provider": "cognia",
                "source": "cognia",
                "knowledge_base_id": knowledge_base_id,
                "knowledge_id": knowledge_id,
                "revision_id": revision_id,
                "revision_number": revision_number,
                "version": str(revision_number),
                "chunk_id": chunk_id,
                "chunk_index": raw.get("chunkIndex"),
                "content": str(raw["chunkText"]),
                "start_offset": raw.get("startOffset"),
                "end_offset": raw.get("endOffset"),
                "approximate_token_count": raw.get("approximateTokenCount"),
                "knowledge_type": raw.get("knowledgeType"),
                "scope": raw.get("scope"),
                "rank": raw.get("rank"),
                "relevance": relevance,
                "retrieved_at": retrieved_at,
            }
            if not validate_retrieval(item):
                raise CogniaContractError("cognia_retrieval_contract_invalid")
            documents.append(item)
            if len(documents) >= limit:
                break

        logger.info(
            "cognia_rag_search_completed",
            count=len(documents),
            knowledge_base_count=len(settings.COGNIA_KNOWLEDGE_BASE_IDS),
        )
        return documents

    async def _search_local(
        self,
        query: str,
        *,
        limit: int,
        min_similarity: float,
        access_scopes: Optional[List[str]],
    ) -> List[Dict[str, Any]]:
        db = self._require_local_db()
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
        result = await db.execute(stmt)
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
                "provider": "local_pgvector",
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

        logger.info(f"Governed local RAG search returned {len(documents)} documents")
        return documents

    async def register_knowledge(
        self,
        *,
        knowledge_base_id: int,
        title: str,
        content: str,
        scope: Dict[str, Any],
        knowledge_type: str = "text",
        tag_ids: Optional[List[int]] = None,
        category_ids: Optional[List[int]] = None,
        metadata: Optional[Dict[str, str]] = None,
        idempotency_key: Optional[str] = None,
    ) -> Dict[str, Any]:
        if self.provider != "cognia":
            raise RuntimeError("governed_knowledge_authoring_requires_cognia")
        if int(knowledge_base_id) not in settings.COGNIA_KNOWLEDGE_BASE_IDS:
            raise ValueError("cognia_knowledge_base_not_configured_for_aiops")
        async with CogniaClient() as client:
            return await client.register_knowledge(
                knowledge_base_id=knowledge_base_id,
                title=title,
                content=content,
                scope=scope,
                knowledge_type=knowledge_type,
                tag_ids=tag_ids,
                category_ids=category_ids,
                metadata=metadata,
                idempotency_key=idempotency_key,
            )

    async def create_revision(
        self,
        *,
        knowledge_base_id: int,
        knowledge_id: int,
        expected_current_candidate_revision_id: Optional[int],
        title: str,
        content: str,
        tag_ids: Optional[List[int]] = None,
        category_ids: Optional[List[int]] = None,
        metadata: Optional[Dict[str, str]] = None,
    ) -> Dict[str, Any]:
        if self.provider != "cognia":
            raise RuntimeError("governed_knowledge_revision_requires_cognia")
        if int(knowledge_base_id) not in settings.COGNIA_KNOWLEDGE_BASE_IDS:
            raise ValueError("cognia_knowledge_base_not_configured_for_aiops")
        async with CogniaClient() as client:
            return await client.create_revision(
                knowledge_base_id=knowledge_base_id,
                knowledge_id=knowledge_id,
                expected_current_candidate_revision_id=expected_current_candidate_revision_id,
                title=title,
                content=content,
                tag_ids=tag_ids,
                category_ids=category_ids,
                metadata=metadata,
            )

    async def get_processing_status(
        self, *, knowledge_base_id: int, knowledge_id: int, revision_id: int
    ) -> Dict[str, Any]:
        if self.provider != "cognia":
            raise RuntimeError("governed_knowledge_processing_status_requires_cognia")
        async with CogniaClient() as client:
            return await client.get_processing_status(
                knowledge_base_id=knowledge_base_id,
                knowledge_id=knowledge_id,
                revision_id=revision_id,
            )

    async def generate_context(
        self,
        task: str,
        *,
        subject: Optional[Dict[str, str]] = None,
        context_profile_id: Optional[int] = None,
    ) -> Dict[str, Any]:
        if self.provider != "cognia":
            raise RuntimeError("context_generation_requires_cognia_provider")
        profile_id = context_profile_id or settings.COGNIA_CONTEXT_PROFILE_ID
        if profile_id is None:
            raise RuntimeError("cognia_context_profile_id_not_configured")
        async with CogniaClient() as client:
            return await client.generate_context(
                task,
                context_profile_id=profile_id,
                subject=subject,
            )

    async def get_all_documents(self, limit: int = 100) -> List[Dict[str, Any]]:
        if self.provider != "local_pgvector":
            raise RuntimeError("cognia_knowledge_listing_requires_explicit_kb_contract")
        db = self._require_local_db()
        stmt = select(KnowledgeDocument).limit(limit)
        result = await db.execute(stmt)
        docs = result.scalars().all()
        return [
            {
                "id": str(doc.id),
                "source_id": str(doc.id),
                "provider": "local_pgvector",
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
        if self.provider != "local_pgvector":
            # Cognia V1 consumer API does not expose Knowledge delete.
            raise RuntimeError("cognia_knowledge_delete_not_supported")
        db = self._require_local_db()
        stmt = select(KnowledgeDocument).where(KnowledgeDocument.id == doc_id)
        result = await db.execute(stmt)
        doc = result.scalar_one_or_none()
        if not doc:
            return False
        await db.delete(doc)
        await db.commit()
        logger.info(f"Deleted local knowledge document: {doc_id}")
        return True
