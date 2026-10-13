from __future__ import annotations

from uuid import UUID
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import desc, select, text

from database import AsyncSessionLocal
from domain.models import Incident, Evidence, Finding, MemoryEntry
from domain.contracts.exceptions import AppException
from apps.api.database_guard import require_database_ready
from apps.rag_service import KnowledgeRAGService
from apps.memory_service import OperationalMemoryService
from apps.memory_service.consolidation import summarize_service
from apps.audit_service.postgres import PostgreSQLAuditStore
from apps.orchestrator.workflow_store import WorkflowCheckpointStore
from apps.operator_summary import build_operator_summary
from apps.security.auth import require_permission
from integrations.cognia import CogniaAPIError, CogniaConfigurationError, CogniaContractError

router = APIRouter(dependencies=[Depends(require_permission("read:incident"))])


class MemoryLifecycleRequest(BaseModel):
    reason: str = Field(min_length=3, max_length=2000)
    superseded_by_memory_id: UUID | None = None


async def _require_current_database_schema(db) -> None:
    await require_database_ready(db, operation="incident_memory_resource")


@router.get("/incidents/{incident_id}/context")
async def get_context(incident_id: UUID):
    async with AsyncSessionLocal() as db:
        incident = await db.get(Incident, incident_id)
        if incident is None:
            raise HTTPException(status_code=404, detail="Incident not found")
        return {
            "incident_id": str(incident.id),
            "service": incident.service,
            "severity": incident.severity,
            "status": incident.status.value if hasattr(incident.status, "value") else str(incident.status),
            "summary": incident.summary,
            "context": incident.context or {},
            "started_at": incident.started_at.isoformat() if incident.started_at else None,
        }


@router.get("/incidents/{incident_id}/evidence")
async def get_evidence(incident_id: UUID, limit: int = Query(default=100, le=500)):
    async with AsyncSessionLocal() as db:
        rows = (
            await db.execute(
                select(Evidence)
                .where(Evidence.incident_id == incident_id)
                .order_by(desc(Evidence.created_at))
                .limit(limit)
            )
        ).scalars().all()
        return {"items": [
            {
                "id": str(row.id),
                "type": row.type.value if hasattr(row.type, "value") else str(row.type),
                "source": row.source,
                "query": row.query,
                "time_range": row.time_range,
                "reference": row.reference,
                "raw_data": row.raw_data,
                "confidence": row.confidence,
            }
            for row in rows
        ]}


@router.get("/incidents/{incident_id}/received-signals")
async def get_received_signals(incident_id: UUID, limit: int = Query(default=60, ge=1, le=100)):
    """Original source notifications from durable Evidence; read-only and RBAC-guarded.

    Old rows were normalized at ingestion, so they are labelled accurately.
    The newer ingress pipeline also retains a size-limited redacted copy of
    the received JSON object. This endpoint never calls a monitoring source.
    """
    from apps.received_signal_view import SOURCE_NAMES, project_received_signal

    async with AsyncSessionLocal() as db:
        incident = await db.get(Incident, incident_id)
        if incident is None:
            raise HTTPException(status_code=404, detail="Incident not found")
        rows = (
            await db.execute(
                select(Evidence)
                .where(Evidence.incident_id == incident_id, Evidence.source.in_(tuple(SOURCE_NAMES)))
                .order_by(Evidence.created_at.asc(), Evidence.id.asc())
                .limit(501)
            )
        ).scalars().all()

    projected = []
    for row in rows:
        item = project_received_signal({
            "id": row.id,
            "source": row.source,
            "reference": row.reference,
            "raw_data": row.raw_data or {},
            "created_at": row.created_at,
        })
        if item is not None:
            projected.append(item)
        if len(projected) > limit:
            break
    return {
        "incident_id": str(incident_id),
        "items": projected[:limit],
        "has_more": len(projected) > limit or len(rows) > 500,
        "source_policy": "durable_source_notification_only",
        "redacted": True,
    }


@router.get("/incidents/{incident_id}/knowledge")
async def get_knowledge(incident_id: UUID, limit: int = Query(default=5, le=20)):
    async with AsyncSessionLocal() as db:
        incident = await db.get(Incident, incident_id)
        if incident is None:
            raise HTTPException(status_code=404, detail="Incident not found")
        query = f"{incident.service or ''} {incident.summary or ''}".strip()
        try:
            items = await KnowledgeRAGService().search(query, limit=limit)
        except CogniaAPIError as exc:
            exposed_status = 503 if exc.status_code in {429, 502, 503, 504} else 502
            raise AppException(
                status_code=exposed_status,
                detail="Governed knowledge provider request failed",
                error_code="COGNIA_RAG_UNAVAILABLE",
                metadata={
                    "provider": "cognia",
                    "upstream_status": exc.status_code,
                    "upstream_code": exc.code,
                    "trace_id": exc.trace_id,
                },
            ) from exc
        except (CogniaConfigurationError, CogniaContractError) as exc:
            raise AppException(
                status_code=502,
                detail="Governed knowledge provider contract is unavailable",
                error_code="COGNIA_RAG_CONTRACT_ERROR",
                metadata={"provider": "cognia", "error_type": type(exc).__name__},
            ) from exc
        return {"provider": "cognia", "items": items}


@router.get("/incidents/{incident_id}/memory")
async def get_memory(incident_id: UUID, limit: int = Query(default=5, le=20)):
    async with AsyncSessionLocal() as db:
        incident = await db.get(Incident, incident_id)
        if incident is None:
            raise HTTPException(status_code=404, detail="Incident not found")
        await _require_current_database_schema(db)
        query = f"{incident.service or ''} {incident.summary or ''}".strip()
        incident_context = incident.context if isinstance(incident.context, dict) else {}
        asset_context = (
            incident_context.get("asset_context")
            if isinstance(incident_context.get("asset_context"), dict)
            else {}
        )
        trigger_context = (
            incident_context.get("trigger_signal")
            if isinstance(incident_context.get("trigger_signal"), dict)
            else {}
        )
        service = OperationalMemoryService(db)
        items = await service.retrieve(
            query,
            service_scope=incident.service,
            environment=None,
            asset_type=asset_context.get("asset_type"),
            signal_type=trigger_context.get("signal_type"),
            service_version=(
                asset_context.get("service_version")
                or incident_context.get("service_version")
            ),
            configuration_fingerprint=(
                asset_context.get("configuration_fingerprint")
                or incident_context.get("configuration_fingerprint")
            ),
            retrieval_mode="SIMILAR_INCIDENT",
            limit=limit,
            target_incident_id=str(incident_id),
            record_retrieval=False,
        )
        current = (
            await db.execute(
                select(MemoryEntry)
                .where(MemoryEntry.incident_id == incident_id)
                .order_by(desc(MemoryEntry.created_at))
                .limit(1)
            )
        ).scalars().first()
        return {
            "policy": {
                "label": "HISTORICAL OPERATIONAL EXPERIENCE",
                "safe_as_evidence": False,
                "requires_current_validation": True,
            },
            "current_episode": service.serialize_entry(current) if current else None,
            # Explicit operator-facing projections; keep "items" for backward compatibility.
            "similar_incidents": items,
            "historical_rca": [
                {
                    "memory_id": item["id"],
                    "status": item.get("root_cause_status"),
                    "confidence": item.get("root_cause_confidence"),
                    "summary": item.get("root_cause"),
                }
                for item in items
            ],
            "previous_actions": [
                {
                    "memory_id": item["id"],
                    "actual_remediation": item.get("actual_remediation") or {},
                    "verification": item.get("verification") or {},
                    "outcome": item.get("memory_outcome_class"),
                    "effectiveness": item.get("effectiveness_score", 0.0),
                    "age_days": item.get("age_days"),
                    "rank": item.get("rank_position"),
                    "similarity": item.get("vector_similarity", 0.0),
                }
                for item in items
            ],
            "failed_previous_attempts": [
                {
                    "memory_id": item["id"],
                    "action": item.get("action"),
                    "outcome": item.get("memory_outcome_class"),
                    "warnings": item.get("failure_warnings") or [],
                }
                for item in items
                if item.get("memory_outcome_class")
                in {"failed_recovery", "partial_recovery", "execution_blocked"}
            ],
            "items": items,
        }


@router.get("/memory/health")
async def get_memory_health():
    async with AsyncSessionLocal() as db:
        await _require_current_database_schema(db)
        stats = await OperationalMemoryService(db).stats()
    return {
        "status": "healthy",
        "source": "postgresql_pgvector",
        "stats": stats,
    }


@router.get("/memory/summary")
async def get_memory_summary(
    service_scope: str = Query(min_length=1, max_length=255),
    limit: int = Query(default=500, ge=1, le=2000),
):
    async with AsyncSessionLocal() as db:
        await _require_current_database_schema(db)
        summary = await summarize_service(
            db,
            service_scope,
            limit=limit,
        )
    return {
        "policy": {
            "label": "CONSOLIDATED HISTORICAL OPERATIONAL EXPERIENCE",
            "safe_as_evidence": False,
            "requires_current_validation": True,
        },
        "summary": summary,
    }


@router.post(
    "/memory/{memory_id}/invalidate",
    dependencies=[Depends(require_permission("execute:approved"))],
)
async def invalidate_memory(memory_id: UUID, request: MemoryLifecycleRequest):
    async with AsyncSessionLocal() as db:
        await _require_current_database_schema(db)
        service = OperationalMemoryService(db)
        changed = await service.invalidate(
            memory_id,
            reason=request.reason,
            superseded_by=request.superseded_by_memory_id,
        )
        if not changed:
            raise HTTPException(status_code=404, detail="Memory entry not found")
        row = await db.get(MemoryEntry, memory_id)
        return {
            "memory_id": str(memory_id),
            "lifecycle_status": row.lifecycle_status if row else None,
            "superseded_by_memory_id": (
                str(row.superseded_by_memory_id)
                if row and row.superseded_by_memory_id
                else None
            ),
        }


@router.post(
    "/memory/{memory_id}/validate",
    dependencies=[Depends(require_permission("execute:approved"))],
)
async def validate_memory(memory_id: UUID):
    async with AsyncSessionLocal() as db:
        await _require_current_database_schema(db)
        service = OperationalMemoryService(db)
        changed = await service.mark_validated(memory_id)
        if not changed:
            raise HTTPException(status_code=404, detail="Memory entry not found")
        row = await db.get(MemoryEntry, memory_id)
        return {
            "memory_id": str(memory_id),
            "lifecycle_status": row.lifecycle_status if row else None,
            "last_validated_at": (
                row.last_validated_at.isoformat()
                if row and row.last_validated_at
                else None
            ),
        }


@router.get("/incidents/{incident_id}/plan")
async def get_plan(incident_id: UUID):
    async with AsyncSessionLocal() as db:
        rows = (
            await db.execute(
                select(Finding)
                .where(Finding.incident_id == incident_id)
                .order_by(desc(Finding.created_at))
                .limit(20)
            )
        ).scalars().all()
        if not rows:
            raise HTTPException(status_code=404, detail="No findings recorded for incident")
        return {"incident_id": str(incident_id), "findings": [
            {
                "agent": row.agent,
                "finding_type": row.finding_type,
                "statement": row.statement,
                "evidence_ids": row.evidence_ids,
                "confidence": row.confidence,
            }
            for row in rows
        ]}


@router.get("/incidents/{incident_id}/verification")
async def get_verification(incident_id: UUID):
    async with AsyncSessionLocal() as db:
        events = await PostgreSQLAuditStore(db).list(str(incident_id), limit=200)
    items = [event for event in events if event.get("event_type") == "verification_completed"]
    return {"incident_id": str(incident_id), "status": "recorded" if items else "not_recorded", "items": items}


@router.get("/incidents/{incident_id}/audit")
async def get_incident_audit(incident_id: UUID):
    async with AsyncSessionLocal() as db:
        items = await PostgreSQLAuditStore(db).list(str(incident_id), 200)
    return {"incident_id": str(incident_id), "items": items}



@router.get("/incidents/{incident_id}/analysis-status")
async def get_incident_analysis_status(incident_id: UUID):
    """Small, read-only polling contract; never starts or resumes a workflow.

    Deliberately omits large audit/history/evidence records so multiple operator
    tabs can observe a long-running analysis without invoking the LLM or MCP.
    """
    async with AsyncSessionLocal() as db:
        row = (await db.execute(text("""
            SELECT i.status::text AS incident_status,
                   (SELECT wc.status::text FROM workflow_checkpoints wc
                    WHERE wc.incident_id=i.id) AS checkpoint_status,
                   (SELECT wc.version FROM workflow_checkpoints wc
                    WHERE wc.incident_id=i.id) AS checkpoint_version,
                   (SELECT wc.state->>'current_node' FROM workflow_checkpoints wc
                    WHERE wc.incident_id=i.id) AS current_node,
                   (SELECT a.status::text FROM approvals a
                    WHERE a.incident_id=i.id ORDER BY a.created_at DESC LIMIT 1) AS approval_status,
                   (SELECT a.approval_id FROM approvals a
                    WHERE a.incident_id=i.id ORDER BY a.created_at DESC LIMIT 1) AS approval_id
            FROM incidents i WHERE i.id=:id
        """), {"id": str(incident_id)})).mappings().first()
    if row is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    status = str(row["incident_status"] or "").lower()
    checkpoint = str(row["checkpoint_status"] or "").lower()
    approval = str(row["approval_status"] or "").lower()
    running = status == "analyzing" and (
        approval == "consumed" or (
            approval not in {"pending", "approved", "rejected"}
            and checkpoint not in {"paused", "completed", "failed"}
        )
    )
    return {
        "incident_id": str(incident_id),
        "incident_status": status,
        "analysis_in_progress": running,
        "analysis_phase": (
            "executing" if running and approval == "consumed"
            else "analyzing" if running
            else "awaiting_approval" if approval in {"pending", "approved"}
            else "completed"
        ),
        "checkpoint_status": row["checkpoint_status"],
        "checkpoint_version": row["checkpoint_version"],
        "current_node": row["current_node"],
        "approval": {
            "approval_id": str(row["approval_id"]) if row["approval_id"] else None,
            "status": approval or None,
        },
    }


@router.get("/incidents/{incident_id}/lifecycle")
async def get_incident_lifecycle(incident_id: UUID):
    """Return durable governance plus structured agent routing/collaboration state."""
    async with AsyncSessionLocal() as db:
        incident = await db.get(Incident, incident_id)
        if incident is None:
            raise HTTPException(status_code=404, detail="Incident not found")
        checkpoint = await WorkflowCheckpointStore(db).load(str(incident_id))
        approval = (
            await db.execute(
                text(
                    "SELECT approval_id,action,risk_level,approver,status,metadata,created_at,approved_at,rejected_at "
                    "FROM approvals WHERE incident_id=:id ORDER BY created_at DESC LIMIT 1"
                ),
                {"id": str(incident_id)},
            )
        ).mappings().first()
        audits = await PostgreSQLAuditStore(db).list(str(incident_id), 200)

    state = (checkpoint or {}).get("state") or {}
    incident_status = str(incident.status.value if hasattr(incident.status, "value") else incident.status).lower()
    checkpoint_status = str((checkpoint or {}).get("status") or "").lower()
    approval_row = dict(approval) if approval else state.get("approval")
    approval_status_value = (approval_row or {}).get("status")
    approval_status = str(
        approval_status_value.value if hasattr(approval_status_value, "value")
        else approval_status_value or ""
    ).lower()
    # A paused workflow awaiting approval is NOT actively analyzing.
    # A consumed approval may be executing until the incident reaches a terminal status.
    analysis_in_progress = incident_status == "analyzing" and (
        approval_status == "consumed"
        or (approval_status not in {"pending", "approved", "rejected"}
            and checkpoint_status not in {"paused", "completed", "failed"})
    )
    return {
        "incident_id": str(incident_id),
        "incident_status": incident_status,
        "analysis_in_progress": analysis_in_progress,
        "analysis_phase": (
            "executing" if analysis_in_progress and approval_status == "consumed"
            else "analyzing" if analysis_in_progress
            else "awaiting_approval" if approval_status in {"pending", "approved"}
            else "completed"
        ),
        "checkpoint_status": (checkpoint or {}).get("status"),
        "checkpoint_version": (checkpoint or {}).get("version"),
        "current_node": state.get("current_node"),
        "triage": state.get("triage_result") or {},
        "routing": state.get("routing") or {},
        "coordination": state.get("coordination") or {},
        "agents": state.get("analysis_results") or [],
        "evidence_rounds": state.get("evidence_rounds", 0),
        "final_plan": state.get("final_plan"),
        "decision": state.get("decision"),
        "evaluation": state.get("evaluation") or {},
        "approval": approval_row,
        "execution": state.get("execution_result"),
        "verification": state.get("verification_result"),
        "terminal_reason": state.get("terminal_reason"),
        "audit": audits,
    }


@router.get("/incidents/{incident_id}/operator-recommendation/fa")
async def get_operator_recommendation_fa(incident_id: UUID):
    """Translate the durable English recommendation solely for Persian display.

    Neither translation nor its failure can change the Incident or authorize
    action. The untouched English plan stays available in operator-summary.
    """
    from apps.recommendation_translation import (
        TranslationUnavailable, translate_recommendation,
    )

    async with AsyncSessionLocal() as db:
        incident = await db.get(Incident, incident_id)
        if incident is None:
            raise HTTPException(status_code=404, detail="Incident not found")
        checkpoint = await WorkflowCheckpointStore(db).load(str(incident_id)) or {}
    state = (checkpoint.get("state") or {})
    if not isinstance(state, dict) or state.get("execution_request"):
        raise HTTPException(status_code=409, detail="free_text_translation_not_required")
    original = state.get("final_plan")
    if isinstance(original, dict):
        import json
        source = json.dumps(original, ensure_ascii=False)
    elif isinstance(original, str):
        source = original.strip()
    else:
        raise HTTPException(status_code=404, detail="no_free_text_recommendation")
    if not source:
        raise HTTPException(status_code=404, detail="no_free_text_recommendation")
    try:
        translated = await translate_recommendation(source)
    except TranslationUnavailable as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from None
    return {
        "incident_id": str(incident_id),
        "language": "fa",
        "text_fa": translated,
        "source": "llm_translation_display_only",
        "execution_authority": False,
    }


@router.get("/incidents/{incident_id}/operator-summary")
async def get_operator_summary(incident_id: UUID):
    """Return a read-only Persian operator summary derived from current durable Incident state."""
    async with AsyncSessionLocal() as db:
        incident = await db.get(Incident, incident_id)
        if incident is None:
            raise HTTPException(status_code=404, detail="Incident not found")
        await _require_current_database_schema(db)

        evidence_rows = (
            await db.execute(
                select(Evidence)
                .where(Evidence.incident_id == incident_id)
                .order_by(desc(Evidence.created_at))
                .limit(500)
            )
        ).scalars().all()
        finding_rows = (
            await db.execute(
                select(Finding)
                .where(Finding.incident_id == incident_id)
                .order_by(desc(Finding.created_at))
                .limit(100)
            )
        ).scalars().all()
        checkpoint = await WorkflowCheckpointStore(db).load(str(incident_id)) or {}
        approval = (
            await db.execute(
                text(
                    "SELECT approval_id,action,risk_level,approver,status,metadata,created_at,approved_at,rejected_at "
                    "FROM approvals WHERE incident_id=:id ORDER BY created_at DESC LIMIT 1"
                ),
                {"id": str(incident_id)},
            )
        ).mappings().first()
        audits = await PostgreSQLAuditStore(db).list(str(incident_id), 200)
        memory_row = (
            await db.execute(
                select(MemoryEntry)
                .where(MemoryEntry.incident_id == incident_id)
                .order_by(desc(MemoryEntry.created_at))
                .limit(1)
            )
        ).scalars().first()

    durable_evidence = [
        {
            "id": str(row.id),
            "type": row.type.value if hasattr(row.type, "value") else str(row.type),
            "source": row.source,
            "query": row.query,
            "reference": row.reference,
            "raw_data": row.raw_data or {},
            "confidence": row.confidence,
            "created_at": row.created_at.isoformat() if row.created_at else None,
        }
        for row in evidence_rows
    ]
    findings = [
        {
            "id": str(row.id),
            "agent": row.agent,
            "finding_type": row.finding_type,
            "statement": row.statement,
            "evidence_ids": row.evidence_ids or [],
            "confidence": row.confidence,
            "created_at": row.created_at.isoformat() if row.created_at else None,
        }
        for row in finding_rows
    ]
    memory_entry = None
    if memory_row is not None:
        memory_entry = {
            "id": str(memory_row.id),
            "verification_result": memory_row.verification_result,
            "outcome": memory_row.outcome,
            "root_cause": memory_row.root_cause,
            "action": memory_row.action,
        }

    return build_operator_summary(
        incident={
            "id": str(incident.id),
            "service": incident.service,
            "severity": incident.severity,
            "status": incident.status.value if hasattr(incident.status, "value") else str(incident.status),
            "summary": incident.summary,
            "context": incident.context or {},
        },
        durable_evidence=durable_evidence,
        findings=findings,
        checkpoint=checkpoint,
        approval=dict(approval) if approval else None,
        audit_events=audits,
        memory_entry=memory_entry,
    )


async def load_decision_brief_for_incident(db, incident_id: UUID) -> dict:
    """Internal builder; reads all contract sections in the caller's transaction."""
    from apps.decision_brief import build_decision_brief
    from domain.models import KnowledgeReview

    incident = await db.get(Incident, incident_id)
    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    checkpoint = await WorkflowCheckpointStore(db).load(str(incident_id)) or {}
    evidence_rows = (
        await db.execute(
            select(Evidence).where(Evidence.incident_id == incident_id)
            .order_by(desc(Evidence.created_at)).limit(500)
        )
    ).scalars().all()
    finding_rows = (
        await db.execute(
            select(Finding).where(Finding.incident_id == incident_id)
            .order_by(desc(Finding.created_at)).limit(100)
        )
    ).scalars().all()
    audit_rows = await PostgreSQLAuditStore(db).list(str(incident_id), 200)
    approval_row = (
        await db.execute(text(
            "SELECT approval_id,action,risk_level,approver,status,metadata,created_at,approved_at,rejected_at "
            "FROM approvals WHERE incident_id=:id ORDER BY created_at DESC LIMIT 1"
        ), {"id": str(incident_id)})
    ).mappings().first()
    memory_row = (
        await db.execute(
            select(MemoryEntry).where(MemoryEntry.incident_id == incident_id)
            .order_by(desc(MemoryEntry.created_at)).limit(1)
        )
    ).scalars().first()
    persisted_evidence = [{
        "id": str(row.id),
        "type": row.type.value if hasattr(row.type, "value") else str(row.type),
        "source": row.source, "reference": row.reference,
        "query": row.query, "raw_data": row.raw_data or {},
        "confidence": row.confidence,
        "created_at": row.created_at.isoformat() if row.created_at else None,
    } for row in evidence_rows]
    persisted_findings = [{
        "id": str(row.id), "agent": row.agent,
        "finding_type": row.finding_type, "statement": row.statement,
        "evidence_ids": row.evidence_ids or [],
        "confidence": row.confidence,
        "created_at": row.created_at.isoformat() if row.created_at else None,
    } for row in finding_rows]
    incident_data = {
        "id": str(incident.id), "service": incident.service,
        "severity": incident.severity,
        "status": incident.status.value if hasattr(incident.status, "value") else str(incident.status),
        "summary": incident.summary, "context": incident.context or {},
        "started_at": incident.started_at.isoformat() if incident.started_at else None,
    }
    operator_summary = build_operator_summary(
        incident=incident_data, durable_evidence=persisted_evidence,
        findings=persisted_findings, checkpoint=checkpoint,
        approval=dict(approval_row) if approval_row else None,
        audit_events=audit_rows,
        memory_entry=(
            {"id": str(memory_row.id), "verification_result": memory_row.verification_result,
             "outcome": memory_row.outcome, "root_cause": memory_row.root_cause,
             "action": memory_row.action}
            if memory_row else None
        ),
    )
    from apps.approval_service.binding import decision_snapshot_digest
    from apps.incident_service.repository import IncidentRepository

    approval_metadata = dict(approval_row["metadata"] or {}) if approval_row else {}
    bound_snapshot = approval_metadata.get("decision_snapshot_digest")
    approval_status = operator_summary["approval"]["status"]
    if bound_snapshot and approval_status in {"pending", "approved"}:
        # Approval is still actionable: compare the immutable pre-execution
        # evidence/plan digest. Runtime authorization performs its own check.
        current_inventory = await IncidentRepository(db).evidence_inventory_digest(str(incident_id))
        current_digest = decision_snapshot_digest(
            checkpoint.get("state") or {}, current_inventory,
        )
        snapshot_status = "matched" if current_digest == bound_snapshot else "drift_detected"
    elif approval_status in {"consumed", "rejected", "expired"}:
        # The old approval cannot authorize another operation. New evidence
        # and execution results legitimately change the snapshot afterwards;
        # calling that "approval drift" is a misleading operator warning.
        snapshot_status = "not_applicable"
    else:
        snapshot_status = "legacy_unbound"
    operator_summary["approval"]["decision_snapshot_status"] = snapshot_status
    memory_id = (operator_summary.get("memory") or {}).get("memory_entry_id")
    latest_review = None
    if memory_id:
        latest_review = (
            await db.execute(
                select(KnowledgeReview).where(
                    KnowledgeReview.incident_id == incident_id,
                    KnowledgeReview.memory_id == UUID(memory_id),
                ).order_by(desc(KnowledgeReview.created_at)).limit(1)
            )
        ).scalars().first()

    return build_decision_brief(
        incident=incident_data,
        operator_summary=operator_summary,
        checkpoint=checkpoint,
        durable_evidence=persisted_evidence,
        findings=persisted_findings,
        audit_events=audit_rows,
        knowledge_review=(
            {"id": str(latest_review.id), "status": latest_review.status}
            if latest_review is not None else None
        ),
    )


@router.get("/incidents/{incident_id}/decision-brief")
async def get_incident_decision_brief(incident_id: UUID):
    """Read-only, RBAC-protected latest version. No archive writes or side effects."""
    async with AsyncSessionLocal() as db:
        # Multiple Incident tables must be read at the same MVCC snapshot.
        # A shared AsyncSession alone is insufficient at READ COMMITTED.
        await db.execute(text("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY"))
        return await load_decision_brief_for_incident(db, incident_id)


@router.get("/incidents/{incident_id}/decision-brief/history")
async def get_decision_brief_history(
    incident_id: UUID, limit: int = Query(default=30, ge=1, le=100),
):
    """Read only previously archived, immutable lifecycle reports."""
    from apps.decision_brief_history import list_decision_brief_history

    async with AsyncSessionLocal() as db:
        if await db.get(Incident, incident_id) is None:
            raise HTTPException(status_code=404, detail="Incident not found")
        return {
            "incident_id": str(incident_id),
            "items": await list_decision_brief_history(db, incident_id, limit),
        }


@router.get("/incidents/{incident_id}/decision-brief/history/{snapshot_id}")
async def get_decision_brief_historical_snapshot(incident_id: UUID, snapshot_id: UUID):
    """Exact archived report; never regenerated against current Incident state."""
    from apps.decision_brief_history import read_decision_brief_snapshot

    async with AsyncSessionLocal() as db:
        if await db.get(Incident, incident_id) is None:
            raise HTTPException(status_code=404, detail="Incident not found")
        brief = await read_decision_brief_snapshot(db, incident_id, snapshot_id)
        if brief is None:
            raise HTTPException(status_code=404, detail="Decision brief snapshot not found")
        return brief


@router.get("/incidents/{incident_id}/decision-brief/narrative")
async def get_incident_decision_brief_narrative(
    incident_id: UUID,
    lang: str = Query(default="fa", pattern="^(fa|en)$"),
):
    """Optional display prose; approval and the deterministic brief stay authoritative."""
    from apps.decision_brief_narrative import generate_narrative

    brief = await get_incident_decision_brief(incident_id)
    return await generate_narrative(brief, lang)
