"""Human-approved AIOps Knowledge Review; never reuses operational approval grants."""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from uuid import UUID, uuid4
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import String, cast, func, or_, select, text

from apps.api.database_guard import require_database_ready
from apps.knowledge_review import (
    configured_kb, content_digest, create_from_memory, get_locked_review,
    review_summary, validated_document,
)
from apps.security.auth import require_permission
from database import AsyncSessionLocal
from domain.contracts.config import settings
from domain.contracts.redaction import redact_text
from domain.models import KnowledgeReview
from integrations.cognia import CogniaClient, CogniaAPIError, CogniaContractError, CogniaConfigurationError

router = APIRouter()


class IncidentDraftRequest(BaseModel):
    memory_id: UUID
    kb_id: int | None = None


class ManualDraftRequest(BaseModel):
    title: str = Field(min_length=1, max_length=500)
    content: str = Field(min_length=1, max_length=1048576)
    kb_id: int | None = None


class ReviewEditRequest(BaseModel):
    title: str = Field(min_length=1, max_length=500)
    content: str = Field(min_length=1, max_length=1048576)
    expected_revision: int = Field(ge=1)


class ReviewEvidenceRefreshRequest(BaseModel):
    expected_revision: int = Field(ge=1)


class ReviewDecisionRequest(BaseModel):
    expected_revision: int = Field(ge=1)
    reason: str = Field(min_length=3, max_length=1000)


async def _audit(db, row: KnowledgeReview, actor: str, event: str) -> None:
    # Durable, atomic with the row mutation, with no draft content or credentials.
    await db.execute(text("""
        INSERT INTO audit_events
        (event_id,event_type,actor,incident_id,action,status,metadata,created_at)
        VALUES (:event_id,:event_type,:actor,:incident_id,:action,:status,
                CAST(:metadata AS jsonb),now())
    """), {
        "event_id": uuid4(), "event_type": "knowledge_" + event,
        "actor": actor, "incident_id": row.incident_id,
        "action": event, "status": row.status,
        "metadata": json.dumps({
            "review_id": str(row.id), "kb_id": row.kb_id,
            "revision": row.revision, "content_hash": row.content_hash,
            "cognia_knowledge_id": row.cognia_knowledge_id,
        }),
    })


@router.post("/knowledge-reviews/reconcile-recent",
             dependencies=[Depends(require_permission("knowledge:draft"))])
async def reconcile_recent_recovery_reviews(
    limit: int = Query(default=30, ge=1, le=50),
):
    """Recover missing *drafts* from verified, immutable execution audit.

    This is a privileged, idempotent local-outbox reconciliation, NOT a Cognia
    write or an approval. It also covers prior incidents where the runbook
    executed successfully but port-listening verification stayed inconclusive.
    """
    from apps.knowledge_review import create_from_governed_service_recovery
    from domain.contracts.logging import logger
    async with AsyncSessionLocal() as db:
        await require_database_ready(db, operation="knowledge_review_reconcile")
        rows = (await db.execute(text("""
            SELECT incident_id, metadata->>'approval_id' AS approval_id
            FROM audit_events
            WHERE event_type='remediation_executed'
              AND metadata->'result'->>'success'='true'
              AND incident_id IS NOT NULL
            ORDER BY created_at DESC LIMIT :limit
        """), {"limit": limit})).mappings().all()
    created = []
    skipped = 0
    failures = []
    seen = set()
    for item in rows:
        try:
            incident_id = UUID(str(item["incident_id"]))
            approval_id = str(item["approval_id"] or "")
        except (ValueError, TypeError):
            skipped += 1
            continue
        if not approval_id or (incident_id, approval_id) in seen:
            skipped += 1
            continue
        seen.add((incident_id, approval_id))
        try:
            async with AsyncSessionLocal() as db:
                review = await create_from_governed_service_recovery(
                    db, incident_id=incident_id, approval_id=approval_id,
                )
                if review:
                    created.append({
                        "incident_id": str(incident_id),
                        "review_id": str(review.id),
                    })
                else:
                    skipped += 1
        except HTTPException as exc:
            logger.warning("knowledge_reconcile_configuration_blocked",
                           incident_id=str(incident_id), status_code=exc.status_code)
            failures.append(str(exc.detail)[:100])
        except Exception as exc:
            logger.warning("knowledge_reconcile_execution_failed",
                           incident_id=str(incident_id), error_type=type(exc).__name__)
            failures.append("knowledge_reconcile_execution_failed")
    return {
        "status": "partial" if failures else "completed",
        "items": created,
        "matched": len(seen), "skipped": skipped,
        "errors": list(dict.fromkeys(failures))[:5],
        "published_to_cognia": False,
        "requires_human_review": True,
    }


@router.post("/knowledge-reviews/reconcile-incidents",
             dependencies=[Depends(require_permission("knowledge:draft"))])
async def reconcile_incident_coverage(
    limit: int = Query(default=40, ge=1, le=100),
    offset: int = Query(default=0, ge=0, le=1000000),
):
    """Backfill every incident *outcome*, not only verified write actions.

    Pages are bounded and idempotent; a rejected/published/edited review is
    never replaced. No Cognia API request and no service write is performed.
    """
    from domain.models import Incident
    from apps.knowledge_incident_coverage import create_from_incident
    from domain.contracts.logging import logger

    async with AsyncSessionLocal() as db:
        await require_database_ready(db, operation="knowledge_incident_coverage")
        ids = (await db.execute(
            select(Incident.id).order_by(
                Incident.created_at.desc(), Incident.id.desc()
            ).offset(offset).limit(limit + 1)
        )).scalars().all()
    created = 0
    existing = 0
    failures = []
    for incident_id in ids[:limit]:
        try:
            async with AsyncSessionLocal() as db:
                _, outcome = await create_from_incident(db, incident_id)
                if outcome == "created":
                    created += 1
                else:
                    existing += 1
        except HTTPException as exc:
            failures.append(str(exc.detail)[:100])
            logger.warning("knowledge_incident_coverage_blocked",
                           incident_id=str(incident_id), code=str(exc.detail)[:100])
        except Exception as exc:
            failures.append("incident_coverage_draft_failed")
            logger.warning("knowledge_incident_coverage_failed",
                           incident_id=str(incident_id), error_type=type(exc).__name__)
    return {
        "status": "partial" if failures else "completed",
        "scanned": min(len(ids), limit),
        "created": created, "existing": existing,
        "failed": len(failures),
        "has_more": len(ids) > limit,
        "next_offset": offset + min(len(ids), limit),
        "errors": list(dict.fromkeys(failures))[:5],
        "published_to_cognia": False,
        "requires_human_review": True,
    }


_REVIEW_SORTS = {
    "created_desc": (KnowledgeReview.created_at.desc(), KnowledgeReview.id.desc()),
    "created_asc": (KnowledgeReview.created_at.asc(), KnowledgeReview.id.asc()),
    "updated_desc": (KnowledgeReview.updated_at.desc(), KnowledgeReview.id.desc()),
    "updated_asc": (KnowledgeReview.updated_at.asc(), KnowledgeReview.id.asc()),
    "title_asc": (KnowledgeReview.title.asc(), KnowledgeReview.id.asc()),
    "status_asc": (KnowledgeReview.status.asc(), KnowledgeReview.created_at.desc(), KnowledgeReview.id.desc()),
}


@router.get("/knowledge-reviews", dependencies=[Depends(require_permission("knowledge:draft"))])
async def list_reviews(
    status: str | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=100),
    offset: int = Query(default=0, ge=0, le=1000000),
    sort_by: Literal["created_desc", "created_asc", "updated_desc", "updated_asc",
                     "title_asc", "status_asc"] = Query(default="created_desc"),
    period_days: int | None = Query(default=None, ge=1, le=365),
    q: str | None = Query(default=None, max_length=100),
):
    filters = []
    if status:
        filters.append(KnowledgeReview.status == status)
    if period_days is not None:
        filters.append(KnowledgeReview.created_at >=
                       datetime.now(timezone.utc) - timedelta(days=period_days))
    if q and q.strip():
        # Escape LIKE metacharacters; a query is literal, not a wildcard scan.
        escaped = q.strip().replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        pattern = "%" + escaped + "%"
        filters.append(or_(
            KnowledgeReview.title.ilike(pattern, escape="\\"),
            cast(KnowledgeReview.incident_id, String).ilike(pattern, escape="\\"),
        ))
    async with AsyncSessionLocal() as db:
        await require_database_ready(db, operation="knowledge_review_list")
        statement = select(KnowledgeReview).where(*filters)
        rows = (await db.execute(statement.order_by(
            *_REVIEW_SORTS[sort_by]
        ).offset(offset).limit(limit + 1))).scalars().all()
        total = (await db.execute(
            select(func.count()).select_from(KnowledgeReview).where(*filters)
        )).scalar_one()
        # Sorting and filtering run in PostgreSQL BEFORE pagination. The list
        # stays metadata-only; full text is returned on explicit selection.
        return {"items": [
            {key: value for key, value in review_summary(row).items() if key != "content"}
            for row in rows[:limit]
        ], "total": total, "sort_by": sort_by,
           "has_more": len(rows) > limit,
           "next_offset": offset + min(len(rows), limit)}


# Aggregated monitoring only. PostgreSQL holds review/outbox and historical
# workflow audit, never Cognia's complete inventory or any RAG vector index.
_MONITOR_REVIEW_SQL = text("""
SELECT status, source_type, COUNT(*) AS count,
       COUNT(*) FILTER (WHERE created_at >= :since) AS created_in_window,
       COUNT(*) FILTER (WHERE published_at >= :since) AS published_in_window,
       COUNT(*) FILTER (WHERE status = 'pending_review' AND created_at < :stale_review) AS overdue_review,
       COUNT(*) FILTER (WHERE status = 'publishing'
                        AND publish_attempted_at < :stale_claim) AS stale_publish,
       COUNT(*) FILTER (WHERE status = 'submitted'
                        AND submitted_at < :stale_activation) AS overdue_activation,
       MAX(published_at) AS latest_published
FROM knowledge_reviews
GROUP BY status, source_type
""")

_MONITOR_TREND_SQL = text("""
SELECT DATE(created_at AT TIME ZONE 'UTC') AS day, COUNT(*) AS count
FROM knowledge_reviews
WHERE created_at >= :trend_since
GROUP BY day ORDER BY day
""")

_MONITOR_PUBLISHED_TREND_SQL = text("""
SELECT DATE(published_at AT TIME ZONE 'UTC') AS day, COUNT(*) AS count
FROM knowledge_reviews
WHERE published_at >= :trend_since
GROUP BY day ORDER BY day
""")

_MONITOR_RAG_SQL = text("""
SELECT metadata->'knowledge_status'->>'status' AS status,
       COUNT(*) AS calls,
       COALESCE(SUM(CASE
         WHEN jsonb_typeof(metadata->'knowledge_count') = 'number'
         THEN (metadata->>'knowledge_count')::integer ELSE 0 END),0) AS returned_items,
       MAX(created_at) AS last_attempt
FROM audit_events
WHERE event_type = 'context_loaded'
  AND created_at >= :since
  AND metadata->'knowledge_status'->>'provider' = 'cognia'
GROUP BY metadata->'knowledge_status'->>'status'
""")

_MONITOR_COVERAGE_SQL = text("""
SELECT (SELECT COUNT(*) FROM incidents) AS incident_total,
       (SELECT COUNT(DISTINCT incident_id) FROM knowledge_reviews
        WHERE incident_id IS NOT NULL) AS incident_with_review
""")


def _knowledge_monitoring_projection(review_rows, created_rows, published_rows,
                                     rag_rows, coverage_row, *, days: int, now: datetime) -> dict:
    """Pure summary: unknown indicators stay explicitly unmeasured."""
    from collections import Counter
    from datetime import date

    states = ("pending_review", "approved", "rejected", "publishing",
              "submitted", "publish_failed", "published")
    totals = Counter()
    sources = Counter()
    created_in_window = 0
    published_in_window = 0
    overdue_review = stale_publish = overdue_activation = 0
    latest_published = None
    for r in review_rows:
        count = int(r["count"] or 0)
        totals[str(r["status"] or "unknown")] += count
        sources[str(r["source_type"] or "unknown")] += count
        created_in_window += int(r["created_in_window"] or 0)
        published_in_window += int(r["published_in_window"] or 0)
        overdue_review += int(r["overdue_review"] or 0)
        stale_publish += int(r["stale_publish"] or 0)
        overdue_activation += int(r["overdue_activation"] or 0)
        last = r["latest_published"]
        if last is not None and (latest_published is None or last > latest_published):
            latest_published = last

    def trend_map(rows):
        result = Counter()
        for row in rows:
            stamp = row["day"]
            key = stamp.isoformat() if isinstance(stamp, date) else str(stamp or "")
            if key:
                result[key] += int(row["count"] or 0)
        return result

    created = trend_map(created_rows)
    published = trend_map(published_rows)
    trend = []
    # A fixed 14-day daily visualization is bounded even with multi-year ledgers.
    for offset in range(13, -1, -1):
        day = (now - timedelta(days=offset)).date().isoformat()
        trend.append({"day": day, "drafted": created[day], "published": published[day]})

    rag_statuses = Counter()
    rag_returned = 0
    rag_total = 0
    last_rag_at = None
    for item in rag_rows:
        name = str(item["status"] or "unknown")
        calls = int(item["calls"] or 0)
        rag_statuses[name] += calls
        rag_total += calls
        rag_returned += int(item["returned_items"] or 0)
        last = item["last_attempt"]
        if last is not None and (last_rag_at is None or last > last_rag_at):
            last_rag_at = last

    incident_total = int(coverage_row["incident_total"] or 0)
    incident_with_review = int(coverage_row["incident_with_review"] or 0)
    return {
        "source": "aiops_postgresql_review_outbox_and_context_audit",
        "period_days": days,
        "sampled_at": now.isoformat(),
        "scope_note": "AIOps local review ledger; not Cognia global KB inventory",
        "reviews": {
            "total": sum(totals.values()),
            "by_status": {status: totals[status] for status in states},
            "other_status": sum(n for k, n in totals.items() if k not in states),
            "by_source": dict(sorted(sources.items())),
            "created_in_period": created_in_window,
            "published_in_period": published_in_window,
            "latest_published_at": latest_published.isoformat() if latest_published else None,
            "review_overdue_24h": overdue_review,
            "publication_stalled_3m": stale_publish,
            "activation_overdue_24h": overdue_activation,
            "daily_last_14_days": trend,
        },
        "coverage": {
            "durable_incidents": incident_total,
            "incidents_with_review": incident_with_review,
            "percentage": round(100 * incident_with_review / incident_total, 1) if incident_total else None,
        },
        "retrieval": {
            "scope": "workflow_context_loaded_audit_only",
            "period_days": days, "observed_calls": rag_total,
            "by_status": dict(sorted(rag_statuses.items())),
            "returned_items_total": rag_returned,
            "last_observed_at": last_rag_at.isoformat() if last_rag_at else None,
            "coverage_complete": False,
            "p95_latency_ms": None,
            "context_relevance": None,
            "groundedness": None,
            "citation_accuracy": None,
        },
        "cognia": {
            "configured_kb_ids": list(settings.COGNIA_KNOWLEDGE_BASE_IDS),
            "global_document_total": None,
            "global_inventory_status": "unavailable_without_authorized_cognia_inventory",
            "health_probe": "/swagger/index.html",
            "health_scope": "http_reachability_only",
        },
    }


@router.get("/knowledge-reviews/monitoring",
            dependencies=[Depends(require_permission("read:incident"))])
async def knowledge_monitoring(days: Literal[7, 30, 90] = Query(default=30)):
    """Read-only operational dashboard, no publication, polling or Cognia writes.

    Metrics are aggregated in PostgreSQL, never by downloading draft contents.
    Retrieval counts include only workflow context_loaded audit observations.
    """
    now = datetime.now(timezone.utc)
    since = now - timedelta(days=days)
    params = {
        "since": since, "trend_since": now - timedelta(days=13),
        "stale_review": now - timedelta(hours=24),
        "stale_claim": now - timedelta(minutes=3),
        "stale_activation": now - timedelta(hours=24),
    }
    async with AsyncSessionLocal() as db:
        await require_database_ready(db, operation="knowledge_monitoring")
        review = (await db.execute(_MONITOR_REVIEW_SQL, params)).mappings().all()
        drafted = (await db.execute(_MONITOR_TREND_SQL, params)).mappings().all()
        published = (await db.execute(_MONITOR_PUBLISHED_TREND_SQL, params)).mappings().all()
        retrieval = (await db.execute(_MONITOR_RAG_SQL, params)).mappings().all()
        coverage = (await db.execute(_MONITOR_COVERAGE_SQL)).mappings().one()
    return _knowledge_monitoring_projection(
        review, drafted, published, retrieval, coverage, days=days, now=now,
    )


@router.get("/knowledge-reviews/{review_id}", dependencies=[Depends(require_permission("knowledge:draft"))])
async def get_review(review_id: UUID):
    async with AsyncSessionLocal() as db:
        await require_database_ready(db, operation="knowledge_review_read")
        row = await db.get(KnowledgeReview, review_id)
        if row is None:
            raise HTTPException(404, "knowledge_review_not_found")
        response = review_summary(row)
        # Display current source-backed Incident facts beside the immutable
        # draft; never silently change text previously edited or approved.
        if row.incident_id:
            from apps.knowledge_review_dossier import incident_dossier
            response["incident_dossier"] = await incident_dossier(db, row.incident_id)
        return response


@router.post("/knowledge-reviews/{review_id}/refresh-evidence",
             dependencies=[Depends(require_permission("knowledge:draft"))])
async def refresh_review_evidence(review_id: UUID,
                                  payload: ReviewEvidenceRefreshRequest,
                                  actor=Depends(require_permission("knowledge:draft"))):
    """Explicit opt-in regeneration of an untouched system-generated draft.

    Never silently rewrite operator edits, approved, rejected or published
    knowledge. Changes invalidate any future approval via revision/hash.
    """
    from apps.knowledge_review_dossier import (
        dossier_addendum, dossier_title, incident_dossier,
    )
    async with AsyncSessionLocal() as db:
        await require_database_ready(db, operation="knowledge_review_refresh")
        row = await get_locked_review(db, review_id)
        if (row.status != "pending_review" or row.incident_id is None
                or not str(row.created_by or "").startswith("system:")
                or row.reviewed_by is not None or row.approved_hash is not None
                or row.revision != 1):
            raise HTTPException(409, "knowledge_draft_not_safe_to_regenerate")
        if row.revision != payload.expected_revision:
            raise HTTPException(409, "review_revision_conflict")
        if row.created_by == "system:incident-coverage":
            if (row.review_reason != "incident_coverage:v1"
                    or row.content_hash != content_digest(row.title, row.content)):
                raise HTTPException(409, "incident_coverage_revision_manually_changed")
            from apps.knowledge_incident_coverage import _source_document
            from domain.models import Incident
            incident = await db.get(Incident, row.incident_id)
            if incident is None:
                raise HTTPException(404, "incident_not_found")
            title, content = await _source_document(db, incident)
            if content_digest(title, content) != row.content_hash:
                row.title, row.content = title, content
                row.content_hash = content_digest(title, content)
                row.revision += 1
                await _audit(db, row, actor.subject, "evidence_refreshed")
                await db.commit()
                await db.refresh(row)
            response = review_summary(row)
            response["incident_dossier"] = await incident_dossier(db, row.incident_id)
            return response
        dossier = await incident_dossier(db, row.incident_id)
        addendum = dossier_addendum(dossier)
        if not addendum:
            raise HTTPException(409, "no_sourced_config_diagnostic_available")
        if "شواهد فنی مرتبط با کانفیگ" in row.content:
            return review_summary(row)
        title = dossier_title(str(dossier.get("service") or "unknown"), dossier,
                              verified_memory=row.source_type == "incident")
        content = row.content + "\n\n" + addendum
        next_title, next_content = validated_document(title or row.title, content)
        row.title, row.content = next_title, next_content
        row.content_hash = content_digest(next_title, next_content)
        row.revision += 1
        row.status = "pending_review"
        row.review_reason = "source_backed_config_diagnostic_review"
        await _audit(db, row, actor.subject, "evidence_refreshed")
        await db.commit()
        await db.refresh(row)
        response = review_summary(row)
        response["incident_dossier"] = dossier
        return response


@router.post("/knowledge-reviews/from-memory", dependencies=[Depends(require_permission("knowledge:draft"))])
async def draft_from_memory(payload: IncidentDraftRequest, actor=Depends(require_permission("knowledge:draft"))):
    async with AsyncSessionLocal() as db:
        await require_database_ready(db, operation="knowledge_review_create")
        row = await create_from_memory(db, payload.memory_id, actor.subject, kb_id=payload.kb_id)
        return review_summary(row)


@router.post("/knowledge-reviews/manual", dependencies=[Depends(require_permission("knowledge:draft"))])
async def draft_manual(payload: ManualDraftRequest, actor=Depends(require_permission("knowledge:draft"))):
    title, content = validated_document(payload.title, payload.content)
    kb_id = configured_kb(payload.kb_id)
    if not settings.COGNIA_CLIENT_APPLICATION_ID:
        raise HTTPException(503, "cognia_client_application_id_not_configured")
    async with AsyncSessionLocal() as db:
        await require_database_ready(db, operation="knowledge_review_create")
        row = KnowledgeReview(
            source_type="manual", kb_id=kb_id,
            scope={"type": "clientApplication", "clientApplicationId": settings.COGNIA_CLIENT_APPLICATION_ID},
            title=title, content=content, content_hash=content_digest(title, content),
            created_by=actor.subject, status="pending_review",
        )
        db.add(row)
        await db.flush()
        await _audit(db, row, actor.subject, "drafted")
        await db.commit()
        await db.refresh(row)
        return review_summary(row)


@router.put("/knowledge-reviews/{review_id}", dependencies=[Depends(require_permission("knowledge:draft"))])
async def edit_review(review_id: UUID, payload: ReviewEditRequest, actor=Depends(require_permission("knowledge:draft"))):
    title, content = validated_document(payload.title, payload.content)
    async with AsyncSessionLocal() as db:
        await require_database_ready(db, operation="knowledge_review_edit")
        row = await get_locked_review(db, review_id)
        if row.status not in {"pending_review", "rejected", "approved"}:
            raise HTTPException(409, "published_or_inflight_review_immutable")
        if row.revision != payload.expected_revision:
            raise HTTPException(409, "review_revision_conflict")
        if row.title == title and row.content == content:
            return review_summary(row)
        row.title, row.content = title, content
        row.content_hash = content_digest(title, content)
        row.revision += 1
        row.status = "pending_review"
        row.approved_hash = None
        row.approved_revision = None
        row.reviewed_by = None
        row.review_reason = None
        row.publish_error_code = None
        await _audit(db, row, actor.subject, "edited")
        await db.commit()
        await db.refresh(row)
        return review_summary(row)


@router.post("/knowledge-reviews/{review_id}/approve", dependencies=[Depends(require_permission("knowledge:review"))])
async def approve_review(review_id: UUID, payload: ReviewDecisionRequest, actor=Depends(require_permission("knowledge:review"))):
    async with AsyncSessionLocal() as db:
        await require_database_ready(db, operation="knowledge_review_approve")
        row = await get_locked_review(db, review_id)
        if row.status != "pending_review" or row.revision != payload.expected_revision:
            raise HTTPException(409, "review_not_pending_or_revision_conflict")
        if row.source_type == "incident":
            # Recheck historical source before approving; source may be invalidated.
            from domain.models import MemoryEntry
            from apps.knowledge_review import memory_is_verified
            source = await db.get(MemoryEntry, row.memory_id)
            if not source or not memory_is_verified(source):
                raise HTTPException(409, "incident_memory_no_longer_verified")
        validated_document(row.title, row.content)
        if content_digest(row.title, row.content) != row.content_hash:
            raise HTTPException(409, "knowledge_content_digest_mismatch")
        row.status = "approved"
        row.reviewed_by = actor.subject
        if redact_text(payload.reason) != payload.reason:
            raise HTTPException(422, "knowledge_review_reason_contains_sensitive_material")
        row.review_reason = payload.reason.strip()
        row.approved_hash = row.content_hash
        row.approved_revision = row.revision
        await _audit(db, row, actor.subject, "approved")
        await db.commit()
        await db.refresh(row)
        return review_summary(row)


@router.post("/knowledge-reviews/{review_id}/reject", dependencies=[Depends(require_permission("knowledge:review"))])
async def reject_review(review_id: UUID, payload: ReviewDecisionRequest, actor=Depends(require_permission("knowledge:review"))):
    async with AsyncSessionLocal() as db:
        await require_database_ready(db, operation="knowledge_review_reject")
        row = await get_locked_review(db, review_id)
        if row.status != "pending_review" or row.revision != payload.expected_revision:
            raise HTTPException(409, "review_not_pending_or_revision_conflict")
        row.status = "rejected"
        row.reviewed_by = actor.subject
        if redact_text(payload.reason) != payload.reason:
            raise HTTPException(422, "knowledge_review_reason_contains_sensitive_material")
        row.review_reason = payload.reason.strip()
        await _audit(db, row, actor.subject, "rejected")
        await db.commit()
        await db.refresh(row)
        return review_summary(row)


@router.post("/knowledge-reviews/{review_id}/publish", dependencies=[Depends(require_permission("knowledge:publish"))])
async def publish_review(review_id: UUID, actor=Depends(require_permission("knowledge:publish"))):
    """Publish with a deterministic Idempotency-Key; no unapproved content crosses."""
    async with AsyncSessionLocal() as db:
        await require_database_ready(db, operation="knowledge_review_publish")
        row = await get_locked_review(db, review_id)
        now = datetime.now(timezone.utc)
        stale = bool(row.publish_attempted_at and now - row.publish_attempted_at > timedelta(minutes=3))
        if row.status not in {"approved", "publish_failed"} and not (row.status == "publishing" and stale):
            raise HTTPException(409, "knowledge_not_approved_or_publication_in_progress")
        if row.approved_hash != row.content_hash or row.approved_revision != row.revision:
            raise HTTPException(409, "knowledge_approval_is_stale")
        if configured_kb(row.kb_id) != row.kb_id:
            raise HTTPException(409, "knowledge_kb_mismatch")
        # Reject cross-application publication, including old records whose
        # configured Client Application identity was rotated.
        if row.scope != {"type": "clientApplication", "clientApplicationId": settings.COGNIA_CLIENT_APPLICATION_ID}:
            raise HTTPException(409, "knowledge_scope_mismatch")
        if row.source_type == "incident":
            from domain.models import MemoryEntry
            from apps.knowledge_review import memory_is_verified
            source = await db.get(MemoryEntry, row.memory_id)
            if not source or not memory_is_verified(source):
                raise HTTPException(409, "incident_memory_no_longer_verified")
        validated_document(row.title, row.content)
        row.status = "publishing"
        row.publish_attempted_at = now
        row.publish_error_code = None
        await _audit(db, row, actor.subject, "publication_claimed")
        await db.commit()
        # Exactly the approved snapshot is sent; never accept body content here.
        title, content, scope, kb_id = row.title, row.content, dict(row.scope), row.kb_id
        key = f"aiops-review-{row.id}-v{row.approved_revision}"

    try:
        async with CogniaClient() as client:
            result = await client.register_knowledge(
                knowledge_base_id=kb_id, title=title, content=content,
                scope=scope, knowledge_type="text", idempotency_key=key,
                metadata={"source": "aiops-reviewed-experience", "review_id": str(review_id)},
            )
        knowledge_id, revision_id = int(result["knowledgeId"]), int(result["revisionId"])
        if knowledge_id <= 0 or revision_id <= 0:
            raise CogniaContractError("cognia_registration_identifiers_invalid")
    except Exception as exc:
        code = exc.code if isinstance(exc, CogniaAPIError) else type(exc).__name__
        async with AsyncSessionLocal() as db:
            row = await get_locked_review(db, review_id)
            if row.status == "publishing":
                row.status = "publish_failed"
                row.publish_error_code = str(code)[:100]
                await _audit(db, row, actor.subject, "publication_failed")
                await db.commit()
        raise HTTPException(502, "cognia_publication_failed") from None

    async with AsyncSessionLocal() as db:
        row = await get_locked_review(db, review_id)
        if row.status != "publishing":
            raise HTTPException(409, "knowledge_publication_state_conflict")
        row.cognia_knowledge_id, row.cognia_revision_id = knowledge_id, revision_id
        row.status = "submitted"  # Registration != Activated/Searchable.
        row.submitted_at = datetime.now(timezone.utc)
        await _audit(db, row, actor.subject, "submitted")
        await db.commit()
        await db.refresh(row)
        return review_summary(row)


@router.post("/knowledge-reviews/{review_id}/refresh", dependencies=[Depends(require_permission("knowledge:publish"))])
async def refresh_review(review_id: UUID, actor=Depends(require_permission("knowledge:publish"))):
    async with AsyncSessionLocal() as db:
        await require_database_ready(db, operation="knowledge_review_refresh")
        row = await db.get(KnowledgeReview, review_id)
        if row is None:
            raise HTTPException(404, "knowledge_review_not_found")
        if row.status not in {"submitted", "published"} or not row.cognia_knowledge_id:
            raise HTTPException(409, "knowledge_not_submitted")
        kb_id, knowledge_id, revision_id = row.kb_id, row.cognia_knowledge_id, row.cognia_revision_id
    try:
        async with CogniaClient() as client:
            detail = await client.get_knowledge_detail(knowledge_base_id=kb_id, knowledge_id=knowledge_id)
        active = detail.get("activeRevision") or {}
        is_active = str(active.get("revisionId") or "") == str(revision_id)
    except Exception:
        raise HTTPException(502, "cognia_activation_check_failed") from None

    async with AsyncSessionLocal() as db:
        row = await get_locked_review(db, review_id)
        if row.status == "submitted" and is_active:
            row.status = "published"
            row.published_at = datetime.now(timezone.utc)
            await _audit(db, row, actor.subject, "published")
            await db.commit()
        await db.refresh(row)
        return review_summary(row)
