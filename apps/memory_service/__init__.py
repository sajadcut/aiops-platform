from __future__ import annotations

from datetime import datetime, timedelta, timezone
import time
from typing import Any, Dict, List, Optional, cast
from uuid import UUID, uuid4

from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from domain.contracts.config import settings
from domain.contracts.logging import logger
from domain.models import MemoryEntry
from knowledge import EmbeddingService

from .feedback import apply_feedback, record_retrieval_events
from .retrieval import candidates, rrf_score
from .telemetry import (
    MEMORY_CREATED_TOTAL,
    MEMORY_EMBEDDING_TOTAL,
    MEMORY_LIFECYCLE_TOTAL,
    MEMORY_RETRIEVAL_LATENCY,
    MEMORY_RETRIEVAL_TOTAL,
)


class OperationalMemoryService:
    SUCCESS_STATUSES = {"success", "succeeded", "verified"}
    NEGATIVE_STATUSES = {"failed", "failure", "partial"}
    VALID_STATUSES = SUCCESS_STATUSES | NEGATIVE_STATUSES | {"inconclusive"}

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
        if status not in self.SUCCESS_STATUSES | self.NEGATIVE_STATUSES:
            raise ValueError("memory_requires_conclusive_verification")
        if not outcome or not str(outcome).strip():
            raise ValueError("memory_requires_outcome")
        if not pattern or not pattern.strip():
            raise ValueError("memory_requires_pattern")
        outcome_class = (
            "successful_recovery"
            if status in self.SUCCESS_STATUSES
            else "partial_recovery"
            if status == "partial"
            else "failed_recovery"
        )
        return await self.add_episode(
            {
                "memory_schema_version": "1.0",
                "incident_id": incident_id,
                "pattern": pattern,
                "symptoms": symptoms,
                "root_cause": root_cause,
                "root_cause_status": "unconfirmed" if root_cause else "unknown",
                "root_cause_confidence": 0.0,
                "action": action,
                "actual_remediation": {"action": action} if action else {},
                "verification_result": status,
                "verification": {"status": status},
                "outcome": outcome,
                "memory_outcome_class": outcome_class,
                "environment": environment,
                "service_scope": service_scope,
                "lifecycle_status": "active",
                "reusable_lesson": outcome,
                "embedding_document": pattern,
                "embedding_document_version": "legacy-compat",
                "search_document": " ".join(
                    str(v)
                    for v in (service_scope, pattern, root_cause, action, outcome)
                    if v
                ),
            }
        )

    async def add_episode(self, episode: Dict[str, Any]) -> UUID:
        pattern = str(episode.get("pattern") or "").strip()
        outcome = str(episode.get("outcome") or "").strip()
        status = str(
            episode.get("verification_result") or "inconclusive"
        ).strip().lower()
        if not pattern:
            raise ValueError("memory_requires_pattern")
        if not outcome:
            raise ValueError("memory_requires_outcome")
        if status not in self.VALID_STATUSES:
            raise ValueError("memory_invalid_verification_status")

        entry = MemoryEntry(
            id=uuid4(),
            incident_id=self._uuid_or_none(episode.get("incident_id")),
            memory_schema_version=str(
                episode.get("memory_schema_version") or "2.0"
            ),
            pattern=pattern,
            symptoms=episode.get("symptoms") or {},
            root_cause=episode.get("root_cause"),
            action=episode.get("action"),
            verification_result=status,
            outcome=outcome,
            environment=episode.get("environment"),
            service_scope=episode.get("service_scope"),
            asset_type=episode.get("asset_type"),
            asset_id=episode.get("asset_id"),
            hostname=episode.get("hostname"),
            fqdn=episode.get("fqdn"),
            platform=episode.get("platform"),
            namespace=episode.get("namespace"),
            service_version=episode.get("service_version"),
            configuration_fingerprint=episode.get(
                "configuration_fingerprint"
            ),
            trigger=episode.get("trigger") or {},
            incident_pattern=episode.get("incident_pattern") or {},
            investigation=episode.get("investigation") or {},
            evidence_provenance=episode.get("evidence_provenance") or {},
            root_cause_status=episode.get("root_cause_status") or "unknown",
            root_cause_confidence=float(
                episode.get("root_cause_confidence") or 0.0
            ),
            causal_factors=episode.get("causal_factors") or [],
            contributing_factors=episode.get("contributing_factors") or [],
            actual_remediation=episode.get("actual_remediation") or {},
            verification=episode.get("verification") or {},
            memory_outcome_class=episode.get(
                "memory_outcome_class"
            ) or "diagnostic_only",
            reusable_lesson=episode.get("reusable_lesson"),
            lifecycle_status=episode.get("lifecycle_status") or "active",
            valid_from=episode.get("valid_from") or datetime.now(timezone.utc),
            embedding_document=episode.get("embedding_document"),
            embedding_status="pending",
            embedding_provider=settings.EMBEDDING_PROVIDER,
            embedding_model=settings.EMBEDDING_MODEL,
            embedding_dimension=settings.EMBEDDING_DIMENSION,
            embedding_version="1",
            embedding_document_version=episode.get(
                "embedding_document_version"
            ) or "1",
            embedding_text_hash=episode.get("embedding_text_hash"),
            search_document=episode.get("search_document") or pattern,
            reuse_count=0,
            retrieval_count=0,
            cited_count=0,
            successful_reuse_count=0,
            failed_reuse_count=0,
            effectiveness_score=0.0,
        )
        self.db.add(entry)
        await self.db.commit()
        await self.db.refresh(entry)
        logger.info(
            "aiops.memory.created",
            memory_id=str(entry.id),
            incident_id=(
                str(entry.incident_id) if entry.incident_id else None
            ),
            service=entry.service_scope,
            outcome_class=entry.memory_outcome_class,
        )
        MEMORY_CREATED_TOTAL.labels(
            outcome_class=str(entry.memory_outcome_class or "unknown")
        ).inc()
        await self._embed_entry(entry)
        return cast(UUID, entry.id)

    async def _embed_entry(self, entry: MemoryEntry) -> bool:
        text_value = str(
            entry.embedding_document or entry.pattern or ""
        ).strip()
        entry_id = entry.id
        try:
            embedding = await EmbeddingService.generate_embedding(text_value)
            entry.embedding = embedding
            entry.embedding_status = "ready"
            entry.embedding_provider = settings.EMBEDDING_PROVIDER
            entry.embedding_model = settings.EMBEDDING_MODEL
            entry.embedding_dimension = settings.EMBEDDING_DIMENSION
            entry.embedded_at = datetime.now(timezone.utc)
            await self.db.commit()
            logger.info(
                "aiops.memory.embedding.generated",
                memory_id=str(entry.id),
                provider=entry.embedding_provider,
                model=entry.embedding_model,
                dimension=entry.embedding_dimension,
            )
            MEMORY_EMBEDDING_TOTAL.labels(outcome="success").inc()
            return True
        except Exception as exc:
            try:
                await self.db.rollback()
            except Exception:
                pass
            try:
                persisted = await self.db.get(MemoryEntry, entry_id)
                if persisted is not None:
                    persisted.embedding = None
                    persisted.embedding_status = "failed"
                    persisted.embedding_provider = settings.EMBEDDING_PROVIDER
                    persisted.embedding_model = settings.EMBEDDING_MODEL
                    persisted.embedding_dimension = settings.EMBEDDING_DIMENSION
                    await self.db.commit()
            except Exception as state_exc:
                try:
                    await self.db.rollback()
                except Exception:
                    pass
                logger.error(
                    "aiops.memory.embedding_state_update_failed",
                    memory_id=str(entry_id),
                    error_type=type(state_exc).__name__,
                )
            logger.warning(
                "aiops.memory.embedding.failed",
                memory_id=str(entry_id),
                error_type=type(exc).__name__,
            )
            MEMORY_EMBEDDING_TOTAL.labels(outcome="failed").inc()
            return False

    async def retrieve(
        self,
        query: str,
        *,
        service_scope: Optional[str] = None,
        environment: Optional[str] = None,
        retrieval_mode: str = "SIMILAR_INCIDENT",
        limit: int = 5,
        min_similarity: float = 0.0,
        successful_only: bool = False,
        target_incident_id: Optional[str] = None,
        record_retrieval: bool = False,
    ) -> List[Dict[str, Any]]:
        started = time.perf_counter()
        raw = await candidates(
            self.db,
            str(query or "").strip(),
            service_scope=service_scope,
            environment=environment,
            mode=retrieval_mode,
            limit=limit,
            successful_only=successful_only,
        )
        ranked: List[Dict[str, Any]] = []
        for item in raw:
            similarity = float(item.get("vector_similarity") or 0.0)
            if item.get("vector_rank") and similarity < min_similarity:
                continue
            entry = cast(MemoryEntry, item["entry"])
            row = self.serialize_entry(entry)
            row.update(
                {
                    "historical_context_label": (
                        "HISTORICAL OPERATIONAL EXPERIENCE"
                    ),
                    "safe_as_evidence": False,
                    "requires_current_validation": True,
                    "retrieval_mode": retrieval_mode,
                    "vector_similarity": round(similarity, 6),
                    "lexical_score": round(
                        float(item.get("lexical_score") or 0.0), 6
                    ),
                    "final_rank_score": round(
                        rrf_score(
                            item,
                            service_scope=service_scope,
                            environment=environment,
                            mode=retrieval_mode,
                        ),
                        8,
                    ),
                }
            )
            ranked.append(row)
        ranked.sort(
            key=lambda row: row["final_rank_score"],
            reverse=True,
        )
        ranked = ranked[: max(1, min(int(limit), 50))]
        for position, item in enumerate(ranked, 1):
            item["rank_position"] = position

        if record_retrieval and target_incident_id and ranked:
            await record_retrieval_events(
                self.db,
                ranked,
                target_incident_id=target_incident_id,
                retrieval_mode=retrieval_mode,
            )
        logger.info(
            "aiops.memory.retrieved",
            count=len(ranked),
            retrieval_mode=retrieval_mode,
            service=service_scope,
            target_incident_id=target_incident_id,
        )
        mode = str(retrieval_mode or "SIMILAR_INCIDENT").upper()
        MEMORY_RETRIEVAL_TOTAL.labels(
            mode=mode,
            outcome="hit" if ranked else "empty",
        ).inc()
        MEMORY_RETRIEVAL_LATENCY.labels(mode=mode).observe(
            max(0.0, time.perf_counter() - started)
        )
        return ranked

    async def search_similar(
        self,
        query: str,
        service_scope: Optional[str] = None,
        limit: int = 5,
        min_similarity: float = 0.0,
        successful_only: bool = True,
    ) -> List[Dict[str, Any]]:
        return await self.retrieve(
            query,
            service_scope=service_scope,
            limit=limit,
            min_similarity=min_similarity,
            successful_only=successful_only,
        )

    async def record_feedback(
        self,
        target_incident_id: str,
        *,
        execution_request: Optional[Dict[str, Any]],
        verification_result: Optional[Dict[str, Any]],
        cited_memory_ids: Optional[List[str]] = None,
    ) -> int:
        return await apply_feedback(
            self.db,
            target_incident_id,
            execution_request=execution_request,
            verification_result=verification_result,
            cited_memory_ids=cited_memory_ids,
        )

    async def backfill_embeddings(self, limit: int = 100) -> Dict[str, int]:
        rows = (
            await self.db.execute(
                select(MemoryEntry)
                .where(
                    or_(
                        MemoryEntry.embedding.is_(None),
                        MemoryEntry.embedding_status.in_(
                            ["pending", "failed", "pending_retry"]
                        ),
                    )
                )
                .order_by(MemoryEntry.created_at.asc())
                .limit(max(1, min(int(limit), 1000)))
            )
        ).scalars().all()
        ready = 0
        failed = 0
        for entry in rows:
            if not entry.embedding_document:
                entry.embedding_document = self._legacy_embedding_document(
                    entry
                )
                entry.embedding_document_version = "legacy-backfill"
            if await self._embed_entry(entry):
                ready += 1
            else:
                failed += 1
        return {
            "selected": len(rows),
            "ready": ready,
            "failed": failed,
        }

    async def mark_stale_entries(self, limit: int = 1000) -> int:
        cutoff = datetime.now(timezone.utc) - timedelta(
            days=int(settings.MEMORY_STALE_AFTER_DAYS)
        )
        rows = (
            await self.db.execute(
                select(MemoryEntry)
                .where(
                    MemoryEntry.lifecycle_status == "active",
                    MemoryEntry.created_at < cutoff,
                    or_(
                        MemoryEntry.last_validated_at.is_(None),
                        MemoryEntry.last_validated_at < cutoff,
                    ),
                )
                .order_by(MemoryEntry.created_at.asc())
                .limit(max(1, min(int(limit), 10000)))
            )
        ).scalars().all()
        if not rows:
            return 0
        for entry in rows:
            entry.lifecycle_status = "stale"
        await self.db.commit()
        MEMORY_LIFECYCLE_TOTAL.labels(status="stale").inc(len(rows))
        logger.info(
            "aiops.memory.stale_marked",
            count=len(rows),
            stale_after_days=settings.MEMORY_STALE_AFTER_DAYS,
        )
        return len(rows)

    async def invalidate(
        self,
        entry_id: UUID,
        *,
        reason: str,
        superseded_by: Optional[UUID] = None,
    ) -> bool:
        entry = await self.db.get(MemoryEntry, entry_id)
        if entry is None:
            return False
        entry.lifecycle_status = "superseded" if superseded_by else "invalidated"
        entry.invalidated_at = datetime.now(timezone.utc)
        entry.invalidation_reason = str(reason or "invalidated")[:2000]
        entry.superseded_by_memory_id = superseded_by
        await self.db.commit()
        logger.info(
            "aiops.memory.invalidated",
            memory_id=str(entry.id),
            lifecycle_status=entry.lifecycle_status,
            superseded_by=str(superseded_by) if superseded_by else None,
        )
        MEMORY_LIFECYCLE_TOTAL.labels(status=entry.lifecycle_status).inc()
        return True

    async def mark_validated(self, entry_id: UUID) -> bool:
        entry = await self.db.get(MemoryEntry, entry_id)
        if entry is None:
            return False
        entry.last_validated_at = datetime.now(timezone.utc)
        if entry.lifecycle_status == "stale":
            entry.lifecycle_status = "active"
        await self.db.commit()
        MEMORY_LIFECYCLE_TOTAL.labels(status="validated").inc()
        return True

    async def update_reuse_count(self, entry_id: UUID) -> None:
        entry = await self.db.get(MemoryEntry, entry_id)
        if entry is not None:
            entry.reuse_count = int(entry.reuse_count or 0) + 1
            entry.last_reused_at = datetime.now(timezone.utc)
            await self.db.commit()

    @staticmethod
    def serialize_entry(entry: MemoryEntry) -> Dict[str, Any]:
        remediation = entry.actual_remediation or {}
        return {
            "id": str(entry.id),
            "source_incident_id": (
                str(entry.incident_id) if entry.incident_id else None
            ),
            "memory_schema_version": entry.memory_schema_version,
            "pattern": entry.pattern,
            "incident_pattern": entry.incident_pattern or {},
            "symptoms": entry.symptoms or {},
            "investigation": entry.investigation or {},
            "evidence_provenance": entry.evidence_provenance or {},
            "root_cause": entry.root_cause,
            "root_cause_status": entry.root_cause_status,
            "root_cause_confidence": float(
                entry.root_cause_confidence or 0.0
            ),
            "actual_remediation": remediation,
            "action": remediation.get("action") or entry.action,
            "verification": entry.verification or {},
            "verification_result": entry.verification_result,
            "outcome": entry.outcome,
            "memory_outcome_class": entry.memory_outcome_class,
            "reusable_lesson": entry.reusable_lesson,
            "environment": entry.environment,
            "service_scope": entry.service_scope,
            "asset_type": entry.asset_type,
            "asset_id": entry.asset_id,
            "hostname": entry.hostname,
            "fqdn": entry.fqdn,
            "platform": entry.platform,
            "namespace": entry.namespace,
            "service_version": entry.service_version,
            "configuration_fingerprint": (
                entry.configuration_fingerprint
            ),
            "lifecycle_status": entry.lifecycle_status,
            "embedding_status": entry.embedding_status,
            "embedding_provider": entry.embedding_provider,
            "embedding_model": entry.embedding_model,
            "embedding_dimension": entry.embedding_dimension,
            "retrieval_count": int(entry.retrieval_count or 0),
            "reuse_count": int(entry.reuse_count or 0),
            "successful_reuse_count": int(
                entry.successful_reuse_count or 0
            ),
            "failed_reuse_count": int(entry.failed_reuse_count or 0),
            "effectiveness_score": float(
                entry.effectiveness_score or 0.0
            ),
            "created_at": (
                entry.created_at.isoformat()
                if entry.created_at
                else None
            ),
        }

    @staticmethod
    def _legacy_embedding_document(entry: MemoryEntry) -> str:
        return "\n".join(
            str(value)
            for value in (
                entry.service_scope,
                entry.pattern,
                entry.root_cause,
                entry.action,
                entry.verification_result,
                entry.outcome,
                entry.reusable_lesson,
            )
            if value
        )

    @staticmethod
    def _uuid_or_none(value: Any) -> Optional[UUID]:
        if isinstance(value, UUID):
            return value
        if not value:
            return None
        try:
            return UUID(str(value))
        except (TypeError, ValueError):
            return None
