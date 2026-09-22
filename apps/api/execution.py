from datetime import datetime, timezone
from typing import Any, Dict
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException

from apps.approval_service.binding import assert_bound, bind_metadata
from apps.approval_service.postgres import PostgreSQLApprovalStore
from apps.audit_service import AuditService
from apps.audit_service.postgres import PostgreSQLAuditStore
from apps.execution_service import ExecutionRequest, ExecutionService
from apps.execution_service.tools.registry import tool_registry
from apps.incident_service.repository import IncidentRepository
from apps.runbook_service.registry import RunbookRegistry
from apps.runbook_service.learning import record_runbook_outcome
from apps.runbook_service.runtime_guard import RunbookRuntimeGuard
from apps.security.auth import require_permission
from apps.security.rbac import allowed
from database import AsyncSessionLocal
from domain.contracts.logging import logger

router = APIRouter()
_VALID_RISK_LEVELS = {"low", "medium", "high", "critical"}


def _normalize_risk_level(value: Any) -> str:
    risk = str(value or "").strip().lower()
    if risk not in _VALID_RISK_LEVELS:
        raise HTTPException(status_code=400, detail="invalid_risk_level")
    return risk


def _approval_record(payload: Dict[str, Any]) -> Dict[str, Any]:
    now = datetime.now(timezone.utc).isoformat()
    metadata = dict(payload.get("metadata", {}))
    binding_complete = all(payload.get(name) not in (None, "") for name in ("incident_id", "tool_name", "action", "target"))
    if binding_complete:
        try:
            metadata = bind_metadata(
                metadata, incident_id=payload["incident_id"], tool_name=payload["tool_name"], action=payload["action"],
                target=payload["target"], parameters=payload.get("parameters", {}), timeout=payload.get("timeout", 30),
                runbook_id=payload.get("runbook_id"), runbook_version=payload.get("runbook_version"),
                rollback=payload.get("rollback", False),
            )
        except (TypeError, ValueError) as exc:
            raise HTTPException(status_code=400, detail="invalid_approval_binding") from exc
    else:
        metadata["binding_complete"] = False

    return {
        "approval_id": str(uuid4()), "incident_id": str(payload["incident_id"]), "action": str(payload["action"]),
        "risk_level": _normalize_risk_level(payload["risk_level"]), "approver": str(payload["approver"]),
        "status": "pending", "metadata": metadata, "created_at": now, "approved_at": None, "rejected_at": None,
    }


def _require_risk_permission(identity, risk_level: str) -> None:
    risk = _normalize_risk_level(risk_level)
    permission = "approve:high_risk" if risk in {"high", "critical"} else "approve:low_risk"
    if not any(allowed(role, permission) for role in identity.roles):
        raise HTTPException(status_code=403, detail="insufficient_approval_risk_permission")


async def _audit_durable(db, event_type: str, actor: str, incident_id: str | None, action: str | None, metadata: Dict[str, Any]) -> None:
    AuditService.record(event_type, actor, incident_id, action, "recorded", metadata)
    await AuditService.flush_to_store(PostgreSQLAuditStore(db), incident_id=incident_id)


def _require_pending(current: Dict[str, Any]) -> None:
    status = str(current.get("status") or "").lower()
    if status == "expired":
        raise HTTPException(status_code=409, detail="approval_expired")
    if status != "pending":
        raise HTTPException(status_code=409, detail="approval_not_pending")


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
        await _audit_durable(db, "approval_requested", identity.subject, record["incident_id"], record["action"], {
            "approval_id": record["approval_id"], "risk_level": record["risk_level"],
            "binding_complete": bool(record["metadata"].get("binding_complete")),
        })
        return saved


@router.get("/approvals/{approval_id}")
async def get_approval(approval_id: str, _user=Depends(require_permission("read:incident"))):
    async with AsyncSessionLocal() as db:
        approval = await PostgreSQLApprovalStore(db).get(approval_id)
    if approval is None:
        raise HTTPException(status_code=404, detail="approval_not_found")
    return approval


@router.post("/approvals/{approval_id}/approve")
async def approve(approval_id: str, identity=Depends(require_permission("approve:low_risk"))):
    async with AsyncSessionLocal() as db:
        store = PostgreSQLApprovalStore(db)
        current = await store.get(approval_id)
        if current is None:
            raise HTTPException(status_code=404, detail="approval_not_found")
        _require_pending(current)
        _require_risk_permission(identity, str(current.get("risk_level")))
        approval = await store.set_status(approval_id, "approved", metadata_patch={"approved_by": identity.subject})
        if not approval or approval.get("status") != "approved":
            raise HTTPException(status_code=409, detail="approval_transition_conflict")
        await _audit_durable(db, "approval_granted", identity.subject, str(current.get("incident_id")), str(current.get("action")), {
            "approval_id": approval_id, "risk_level": current.get("risk_level"),
        })
        return approval


@router.post("/approvals/{approval_id}/reject")
async def reject(approval_id: str, payload: Dict[str, Any], identity=Depends(require_permission("approve:low_risk"))):
    reason = str(payload.get("reason") or "").strip()
    if not reason:
        raise HTTPException(status_code=400, detail="rejection_reason_required")
    if len(reason) > 1000:
        raise HTTPException(status_code=400, detail="rejection_reason_too_long")
    async with AsyncSessionLocal() as db:
        store = PostgreSQLApprovalStore(db)
        current = await store.get(approval_id)
        if current is None:
            raise HTTPException(status_code=404, detail="approval_not_found")
        _require_pending(current)
        _require_risk_permission(identity, str(current.get("risk_level")))
        approval = await store.set_status(approval_id, "rejected", metadata_patch={"rejection_reason": reason, "rejected_by": identity.subject})
        if not approval or approval.get("status") != "rejected":
            raise HTTPException(status_code=409, detail="approval_transition_conflict")
        await _audit_durable(db, "approval_rejected", identity.subject, str(current.get("incident_id")), str(current.get("action")), {
            "approval_id": approval_id, "risk_level": current.get("risk_level"), "reason": reason,
        })
        return approval


def _direct_runtime_contract(payload: Dict[str, Any]) -> Dict[str, Any]:
    tool_name = str(payload.get("tool_name") or "").strip()
    action = str(payload.get("action") or "").strip()
    parameters = dict(payload.get("parameters") or {})
    service = str(parameters.get("service") or "").strip()

    if (
        tool_name == "ssh_vm"
        and action in {"start_service", "restart_service"}
        and service
    ):
        requested_runbook = str(payload.get("runbook_id") or "").strip()
        if requested_runbook and requested_runbook != RunbookRuntimeGuard.VM_SERVICE_RUNBOOK:
            raise HTTPException(
                status_code=409,
                detail="direct_execution_runbook_contract_mismatch",
            )
        return {
            "runbook_id": RunbookRuntimeGuard.VM_SERVICE_RUNBOOK,
            "service": service,
        }

    raise HTTPException(
        status_code=409,
        detail="direct_execution_runtime_contract_required",
    )


def _validate_approval_binding(approval: Dict[str, Any], payload: Dict[str, Any]) -> None:
    incident_id = payload.get("incident_id")
    if incident_id is None:
        raise HTTPException(status_code=400, detail="incident_id_required_for_approval")
    try:
        assert_bound(
            approval, incident_id=incident_id, tool_name=payload.get("tool_name"), action=payload.get("action"),
            target=payload.get("target"), parameters=payload.get("parameters", {}), timeout=payload.get("timeout", 30),
            runbook_id=payload.get("runbook_id"), runbook_version=payload.get("runbook_version"),
            rollback=payload.get("rollback", False),
        )
    except (TypeError, ValueError) as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.post("/execute")
async def execute(payload: Dict[str, Any], identity=Depends(require_permission("execute:approved"))):
    required_fields = ["tool_name", "action", "target"]
    missing = [field for field in required_fields if field not in payload]
    if missing:
        raise HTTPException(status_code=400, detail={"code": "MISSING_FIELDS", "fields": missing})

    tool_name = str(payload["tool_name"])
    tool = tool_registry.get_tool(tool_name)
    if tool is None:
        raise HTTPException(status_code=400, detail="tool_not_registered")
    approval_id = payload.get("approval_id")
    incident_id = str(payload.get("incident_id") or "")
    approval_granted = False
    consumed = None
    runtime_contract = None
    before_snapshot = None
    after_snapshot = None
    runbook = None

    async with AsyncSessionLocal() as db:
        if tool.requires_approval:
            if not approval_id:
                raise HTTPException(status_code=400, detail="approval_id_required")
            if not incident_id:
                raise HTTPException(status_code=400, detail="incident_id_required_for_approval")
            store = PostgreSQLApprovalStore(db)
            approval = await store.get(str(approval_id))
            if approval is None:
                raise HTTPException(status_code=404, detail="approval_not_found")
            _validate_approval_binding(approval, payload)

            runtime_contract = _direct_runtime_contract(payload)
            runbook = RunbookRegistry("runbooks").get(
                runtime_contract["runbook_id"]
            )
            before_snapshot = await RunbookRuntimeGuard.collect_snapshot(
                runbook_id=runtime_contract["runbook_id"],
                target=str(payload["target"]),
                parameters=dict(payload.get("parameters") or {}),
                incident_id=incident_id,
                phase="pre",
            )
            precondition = RunbookRuntimeGuard.preflight(
                runbook_id=runtime_contract["runbook_id"],
                tool_name=tool_name,
                action=str(payload["action"]),
                target=str(payload["target"]),
                parameters=dict(payload.get("parameters") or {}),
                incident_id=incident_id,
                evidence=list(before_snapshot.get("evidence") or []),
            )
            if not precondition.get("safe_to_execute"):
                revoked = None
                if RunbookRuntimeGuard.approval_should_be_revoked(precondition):
                    revoked = await store.cancel(
                        str(approval_id),
                        reason="fresh_precondition_invalidated_approved_intent",
                        metadata_patch={
                            "precondition_reason": precondition.get("reason"),
                            "revoked_before_execution": True,
                        },
                    )
                await _audit_durable(
                    db,
                    "direct_execution_precondition_failed",
                    identity.subject,
                    incident_id,
                    str(payload["action"]),
                    {
                        "approval_id": approval_id,
                        "tool_name": tool_name,
                        "target": payload["target"],
                        "runbook_id": runtime_contract["runbook_id"],
                        "precondition": precondition,
                        "snapshot_error": before_snapshot.get("error"),
                        "approval_revoked": bool(
                            revoked and revoked.get("status") == "rejected"
                        ),
                    },
                )
                raise HTTPException(
                    status_code=409,
                    detail=(
                        "direct_execution_precondition_failed:"
                        + str(
                            precondition.get("reason")
                            or "runtime_precondition_failed"
                        )
                    ),
                )

            consumed = await store.consume(str(approval_id), issue_claim=True)
            if not consumed or consumed.get("status") != "consumed":
                raise HTTPException(status_code=409, detail="approval_already_consumed_or_unavailable")
            approval_granted = True
            await _audit_durable(db, "approval_consumed", identity.subject, incident_id, str(payload["action"]), {
                "approval_id": approval_id, "tool_name": tool_name, "target": payload["target"],
            })
        elif approval_id:
            raise HTTPException(status_code=400, detail="approval_not_applicable_to_tool")

        request = ExecutionRequest(
            tool_name=tool_name, action=str(payload["action"]), target=str(payload["target"]),
            parameters=payload.get("parameters", {}), timeout=int(payload.get("timeout", 30)),
            agent_name=str(payload.get("agent_name", "api")), incident_id=incident_id or None,
            approval_granted=approval_granted,
            approval_id=str(approval_id) if approval_id else None,
            runbook_id=payload.get("runbook_id"), runbook_version=payload.get("runbook_version"),
            rollback=bool(payload.get("rollback", False)),
            execution_claim=(consumed or {}).get("_execution_claim"),
        )
        result = await ExecutionService.execute(request)

        response = result.model_dump()
        verification_payload = None
        verified = None
        if tool.requires_approval:
            if result.success:
                after_snapshot = await RunbookRuntimeGuard.collect_snapshot(
                    runbook_id=runtime_contract["runbook_id"],
                    target=request.target,
                    parameters=dict(request.parameters or {}),
                    incident_id=incident_id,
                    phase="post",
                )
                verification = await RunbookRuntimeGuard.verify(
                    runbook=runbook,
                    action=request.action,
                    service=runtime_contract["service"],
                    before_context=dict(
                        (before_snapshot or {}).get("context") or {}
                    ),
                    after_context=dict(
                        after_snapshot.get("context") or {}
                    ),
                )
                verification_payload = verification.model_dump(mode="json")
                verification_payload["snapshot_error"] = after_snapshot.get(
                    "error"
                )
                verified = (
                    verification.status.value == "success"
                    and verification.required_objectives_met is True
                )
            else:
                verification_payload = {
                    "status": "failed",
                    "verification_policy": "execution_failed_before_verification",
                    "required_objectives_met": False,
                    "message": (
                        result.error
                        or result.reason
                        or "Direct execution failed before recovery verification."
                    ),
                }
                verified = False

            response["precondition"] = precondition
            response["verification"] = verification_payload
            response["verified"] = verified

        memory_id = None
        memory_error = None
        if (
            tool.requires_approval
            and runtime_contract
            and runbook
            and consumed
        ):
            try:
                memory_id = await record_runbook_outcome(
                    db,
                    incident_id=incident_id,
                    runbook=runbook,
                    tool_name=request.tool_name,
                    action=request.action,
                    target=request.target,
                    parameters=dict(request.parameters or {}),
                    approval=consumed,
                    execution_result=result.model_dump(mode="json"),
                    verification_result=dict(verification_payload or {}),
                    before_snapshot=before_snapshot,
                    after_snapshot=after_snapshot,
                )
                if memory_id:
                    response["operational_memory_writeback"] = {
                        "memory_id": memory_id,
                        "verification_status": (
                            verification_payload or {}
                        ).get("status"),
                    }
            except Exception as exc:
                memory_error = type(exc).__name__
                logger.error(
                    "direct_execution_operational_memory_writeback_failed",
                    incident_id=incident_id,
                    tool_name=request.tool_name,
                    action=request.action,
                    error_type=memory_error,
                )

        incident_status = None
        if incident_id and verified is not None:
            incidents = IncidentRepository(db)
            incident_status = await incidents.record_operational_outcome(
                incident_id,
                source="direct_execution",
                action=request.action,
                target=request.target,
                approval_id=str(approval_id) if approval_id else None,
                execution_success=bool(result.success),
                verified=bool(verified),
                verification=dict(verification_payload or {}),
                memory_id=memory_id,
            )
            await incidents.commit()
            response["incident_status"] = incident_status

        await _audit_durable(
            db,
            "direct_execution_completed",
            identity.subject,
            incident_id or None,
            request.action,
            {
                "tool_name": request.tool_name,
                "target": request.target,
                "success": result.success,
                "blocked": result.execution_blocked,
                "approval_id": approval_id,
                "verified": verified,
                "verification": verification_payload,
                "memory_id": memory_id,
                "memory_error": memory_error,
                "incident_status": incident_status,
            },
        )
        return response
