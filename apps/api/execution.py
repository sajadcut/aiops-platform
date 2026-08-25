from datetime import datetime, timezone
from typing import Any, Dict
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException

from apps.approval_service.postgres import PostgreSQLApprovalStore
from apps.audit_service import AuditService
from apps.audit_service.postgres import PostgreSQLAuditStore
from apps.execution_service import ExecutionRequest, ExecutionService
from apps.security.auth import require_permission
from apps.security.rbac import allowed
from database import AsyncSessionLocal

router = APIRouter()


def _approval_record(payload: Dict[str, Any]) -> Dict[str, Any]:
    now = datetime.now(timezone.utc).isoformat()
    metadata = dict(payload.get("metadata", {}))
    if payload.get("target") is not None:
        metadata.setdefault("target", str(payload["target"]))
    if payload.get("tool_name") is not None:
        metadata.setdefault("tool_name", str(payload["tool_name"]))
    metadata["binding_complete"] = bool(metadata.get("target") and metadata.get("tool_name"))
    return {
        "approval_id": str(uuid4()),
        "incident_id": str(payload["incident_id"]),
        "action": str(payload["action"]),
        "risk_level": str(payload["risk_level"]).lower(),
        "approver": str(payload["approver"]),
        "status": "pending",
        "metadata": metadata,
        "created_at": now,
        "approved_at": None,
        "rejected_at": None,
    }


def _require_risk_permission(identity, risk_level: str) -> None:
    permission = "approve:high_risk" if str(risk_level).lower() == "high" else "approve:low_risk"
    if not any(allowed(role, permission) for role in identity.roles):
        raise HTTPException(status_code=403, detail="insufficient_approval_risk_permission")


async def _audit_durable(db, event_type: str, actor: str, incident_id: str | None, action: str | None, metadata: Dict[str, Any]) -> None:
    AuditService.record(event_type, actor, incident_id, action, "recorded", metadata)
    await AuditService.flush_to_store(PostgreSQLAuditStore(db), incident_id=incident_id)


@router.post("/approvals")
async def create_approval(payload: Dict[str, Any], identity=Depends(require_permission("approve:low_risk"))):
    required_fields = ["incident_id", "action", "risk_level", "approver"]
    missing = [field for field in required_fields if field not in payload]
    if missing:
        raise HTTPException(status_code=400, detail={"code": "MISSING_FIELDS", "fields": missing})
    _require_risk_permission(identity, str(payload["risk_level"]))
    record = _approval_record(payload)
    async with AsyncSessionLocal() as db:
        saved = await PostgreSQLApprovalStore(db).save(record)
        await _audit_durable(db, "approval_requested", identity.subject, record["incident_id"], record["action"], {"approval_id": record["approval_id"], "risk_level": record["risk_level"], "binding_complete": record["metadata"]["binding_complete"]})
        return saved


@router.get("/approvals/{approval_id}")
async def get_approval(approval_id: str, _user=Depends(require_permission("read:incident"))):
    async with AsyncSessionLocal() as db:
        approval = await PostgreSQLApprovalStore(db).get(approval_id)
    if approval is None:
        raise HTTPException(status_code=404, detail="Approval not found")
    return approval


@router.post("/approvals/{approval_id}/approve")
async def approve(approval_id: str, identity=Depends(require_permission("approve:low_risk"))):
    async with AsyncSessionLocal() as db:
        store = PostgreSQLApprovalStore(db)
        current = await store.get(approval_id)
        if current is None:
            raise HTTPException(status_code=404, detail="Approval not found")
        _require_risk_permission(identity, str(current.get("risk_level")))
        approval = await store.set_status(approval_id, "approved")
        if approval and approval.get("status") == "expired":
            raise HTTPException(status_code=409, detail="Approval expired")
        await _audit_durable(db, "approval_granted", identity.subject, str(current.get("incident_id")), str(current.get("action")), {"approval_id": approval_id, "risk_level": current.get("risk_level")})
        return approval


@router.post("/approvals/{approval_id}/reject")
async def reject(approval_id: str, identity=Depends(require_permission("approve:low_risk"))):
    async with AsyncSessionLocal() as db:
        store = PostgreSQLApprovalStore(db)
        current = await store.get(approval_id)
        if current is None:
            raise HTTPException(status_code=404, detail="Approval not found")
        _require_risk_permission(identity, str(current.get("risk_level")))
        approval = await store.set_status(approval_id, "rejected")
        await _audit_durable(db, "approval_rejected", identity.subject, str(current.get("incident_id")), str(current.get("action")), {"approval_id": approval_id, "risk_level": current.get("risk_level")})
        return approval


def _validate_approval_binding(approval: Dict[str, Any], payload: Dict[str, Any]) -> None:
    if approval.get("status") != "approved":
        raise HTTPException(status_code=409, detail="Approval is not approved")
    incident_id = payload.get("incident_id")
    if incident_id is None:
        raise HTTPException(status_code=400, detail="incident_id is required when approval_id is supplied")
    if str(approval.get("incident_id")) != str(incident_id):
        raise HTTPException(status_code=409, detail="Approval incident does not match execution request")
    if str(approval.get("action")) != str(payload.get("action")):
        raise HTTPException(status_code=409, detail="Approval action does not match execution request")
    metadata = approval.get("metadata") or {}
    if not metadata.get("binding_complete") or not metadata.get("target") or not metadata.get("tool_name"):
        raise HTTPException(status_code=409, detail="Approval is not bound to a tool and target")
    if str(metadata["target"]) != str(payload.get("target")):
        raise HTTPException(status_code=409, detail="Approval target does not match execution request")
    if str(metadata["tool_name"]) != str(payload.get("tool_name")):
        raise HTTPException(status_code=409, detail="Approval tool does not match execution request")


@router.post("/execute")
async def execute(payload: Dict[str, Any], identity=Depends(require_permission("execute:approved"))):
    required_fields = ["tool_name", "action", "target"]
    missing = [field for field in required_fields if field not in payload]
    if missing:
        raise HTTPException(status_code=400, detail={"code": "MISSING_FIELDS", "fields": missing})

    approval_id = payload.get("approval_id")
    approval_granted = False
    approval = None
    async with AsyncSessionLocal() as db:
        if approval_id:
            store = PostgreSQLApprovalStore(db)
            approval = await store.get(str(approval_id))
            if approval is None:
                raise HTTPException(status_code=404, detail="Approval not found")
            _validate_approval_binding(approval, payload)
            consumed = await store.consume(str(approval_id))
            if not consumed or consumed.get("status") != "consumed":
                raise HTTPException(status_code=409, detail="Approval already consumed or unavailable")
            approval_granted = True
            await _audit_durable(db, "approval_consumed", identity.subject, str(approval.get("incident_id")), str(payload["action"]), {"approval_id": approval_id, "tool_name": payload["tool_name"], "target": payload["target"]})

        request = ExecutionRequest(
            tool_name=str(payload["tool_name"]),
            action=str(payload["action"]),
            target=str(payload["target"]),
            parameters=payload.get("parameters", {}),
            timeout=int(payload.get("timeout", 30)),
            agent_name=str(payload.get("agent_name", "api")),
            approval_granted=approval_granted,
            approval_id=approval_id,
        )
        result = await ExecutionService.execute(request)
        incident_id = str(payload.get("incident_id")) if payload.get("incident_id") else None
        await _audit_durable(db, "direct_execution_completed", identity.subject, incident_id, request.action, {"tool_name": request.tool_name, "target": request.target, "success": result.success, "blocked": result.execution_blocked, "approval_id": approval_id})
        return result.model_dump()
