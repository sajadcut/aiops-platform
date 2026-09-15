import math
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from domain.contracts.config import settings
from domain.contracts.logging import log_workflow_step, logger
from integrations.cognia import CogniaClient, CogniaContractError
from knowledge.retrieval_contract import validate_retrieval


class KnowledgeRAGService:
    """Cognia-only governed Knowledge RAG boundary.

    Cognia owns Knowledge Base permissions, Knowledge/Revision lifecycle, Scope,
    Search and Context policy. PostgreSQL/pgvector is reserved for Operational
    Memory and is never a fallback Knowledge RAG provider.
    """

    async def search(
        self,
        query: str,
        limit: int = 5,
        min_similarity: Optional[float] = None,
        access_scopes: Optional[List[str]] = None,
        scope_context: Optional[Dict[str, Any]] = None,
        *,
        incident_id: Optional[str] = None,
        phase: str = "knowledge_rag",
    ) -> List[Dict[str, Any]]:
        # access_scopes is retained only for call compatibility during migration;
        # Cognia is authoritative for KB grants and Scope authorization.
        del access_scopes
        if not query.strip():
            log_workflow_step(
                incident_id=incident_id,
                stage=phase,
                component="cognia_rag",
                action="search_skipped",
                status="skipped",
                summary="Cognia RAG search skipped because the query was empty",
                details={"query_chars": 0, "limit": limit},
            )
            return []
        if limit <= 0:
            raise ValueError("knowledge_search_limit_must_be_positive")
        min_relevance: Optional[float] = None
        if min_similarity is not None:
            min_relevance = float(min_similarity)
            if not math.isfinite(min_relevance):
                raise ValueError("knowledge_min_relevance_must_be_finite")

        log_workflow_step(
            incident_id=incident_id,
            stage=phase,
            component="cognia_rag",
            action="search_started",
            status="started",
            summary="Cognia Knowledge RAG search started",
            details={
                "query_chars": len(query),
                "limit": limit,
                "min_relevance": min_relevance,
                "knowledge_base_count": len(settings.COGNIA_KNOWLEDGE_BASE_IDS),
                "subject_scoped": bool(scope_context),
            },
        )
        try:
            documents = await self._search_cognia(
                query,
                limit=limit,
                min_relevance=min_relevance,
                scope_context=scope_context,
            )
        except Exception as exc:
            log_workflow_step(
                incident_id=incident_id,
                stage=phase,
                component="cognia_rag",
                action="search_failed",
                status="failed",
                summary="Cognia Knowledge RAG search failed",
                details={"error_type": type(exc).__name__, "query_chars": len(query)},
                level="warning",
            )
            raise

        log_workflow_step(
            incident_id=incident_id,
            stage=phase,
            component="cognia_rag",
            action="search_completed",
            status="completed",
            summary=f"Cognia Knowledge RAG returned {len(documents)} result(s)",
            details={
                "result_count": len(documents),
                "source_ids": [str(item.get("source_id")) for item in documents[:10]],
                "max_relevance": max((float(item.get("relevance", 0.0)) for item in documents), default=None),
            },
        )
        return documents

    async def _search_cognia(
        self,
        query: str,
        *,
        limit: int,
        min_relevance: Optional[float],
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
            if not math.isfinite(relevance):
                raise CogniaContractError("cognia_relevance_score_not_finite")
            if min_relevance is not None and relevance < min_relevance:
                continue

            knowledge_base_id = int(raw["knowledgeBaseId"])
            knowledge_id = int(raw["knowledgeId"])
            revision_id = int(raw["revisionId"])
            revision_number = int(raw["revisionNumber"])
            chunk_id = int(raw["chunkId"])
            source_id = f"cognia:{knowledge_base_id}:{knowledge_id}:{revision_id}:{chunk_id}"
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

    @staticmethod
    def _ensure_configured_kb(knowledge_base_id: int) -> int:
        kb_id = int(knowledge_base_id)
        if kb_id <= 0:
            raise ValueError("cognia_knowledge_base_id_must_be_positive")
        if kb_id not in settings.COGNIA_KNOWLEDGE_BASE_IDS:
            raise ValueError("cognia_knowledge_base_not_configured_for_aiops")
        return kb_id

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
        kb_id = self._ensure_configured_kb(knowledge_base_id)
        async with CogniaClient() as client:
            return await client.register_knowledge(
                knowledge_base_id=kb_id,
                title=title,
                content=content,
                scope=scope,
                knowledge_type=knowledge_type,
                tag_ids=tag_ids,
                category_ids=category_ids,
                metadata=metadata,
                idempotency_key=idempotency_key,
            )

    async def get_knowledge_detail(
        self, *, knowledge_base_id: int, knowledge_id: int
    ) -> Dict[str, Any]:
        kb_id = self._ensure_configured_kb(knowledge_base_id)
        knowledge = int(knowledge_id)
        if knowledge <= 0:
            raise ValueError("cognia_knowledge_id_must_be_positive")
        async with CogniaClient() as client:
            return await client.get_knowledge_detail(
                knowledge_base_id=kb_id,
                knowledge_id=knowledge,
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
        kb_id = self._ensure_configured_kb(knowledge_base_id)
        async with CogniaClient() as client:
            return await client.create_revision(
                knowledge_base_id=kb_id,
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
        kb_id = self._ensure_configured_kb(knowledge_base_id)
        async with CogniaClient() as client:
            return await client.get_processing_status(
                knowledge_base_id=kb_id,
                knowledge_id=knowledge_id,
                revision_id=revision_id,
            )

    async def generate_context(
        self,
        task: str,
        *,
        subject: Optional[Dict[str, str]] = None,
        context_profile_id: Optional[int] = None,
        incident_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        profile_id = context_profile_id or settings.COGNIA_CONTEXT_PROFILE_ID
        if profile_id is None:
            raise RuntimeError("cognia_context_profile_id_not_configured")
        log_workflow_step(
            incident_id=incident_id,
            stage="knowledge_rag",
            component="cognia_context",
            action="context_generation_started",
            status="started",
            summary="Cognia context generation started",
            details={"task_chars": len(task), "subject_scoped": bool(subject), "context_profile_id": profile_id},
        )
        try:
            async with CogniaClient() as client:
                result = await client.generate_context(
                    task,
                    context_profile_id=profile_id,
                    subject=subject,
                )
        except Exception as exc:
            log_workflow_step(
                incident_id=incident_id,
                stage="knowledge_rag",
                component="cognia_context",
                action="context_generation_failed",
                status="failed",
                summary="Cognia context generation failed",
                details={"error_type": type(exc).__name__},
                level="warning",
            )
            raise
        log_workflow_step(
            incident_id=incident_id,
            stage="knowledge_rag",
            component="cognia_context",
            action="context_generation_completed",
            status="completed",
            summary="Cognia context generation completed",
            details={"is_sufficient": result.get("isSufficient") if isinstance(result, dict) else None},
        )
        return result
