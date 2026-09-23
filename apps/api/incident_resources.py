from __future__ import annotations

from uuid import UUID
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import desc, select, text

from database import AsyncSessionLocal
from domain.models import Incident, Evidence, Finding, MemoryEntry
from domain.contracts.exceptions import AppException
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
    return {
        "incident_id": str(incident_id),
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
        "approval": dict(approval) if approval else state.get("approval"),
        "execution": state.get("execution_result"),
        "verification": state.get("verification_result"),
        "terminal_reason": state.get("terminal_reason"),
        "audit": audits,
    }


@router.get("/incidents/{incident_id}/operator-summary")
async def get_operator_summary(incident_id: UUID):
    """Return a read-only Persian operator summary derived from current durable Incident state."""
    async with AsyncSessionLocal() as db:
        incident = await db.get(Incident, incident_id)
        if incident is None:
            raise HTTPException(status_code=404, detail="Incident not found")

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
