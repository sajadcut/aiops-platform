from __future__ import annotations

from typing import Any, Dict

from fastapi import APIRouter, Depends, HTTPException

from apps.approval_service.binding import assert_bound
from apps.approval_service.postgres import PostgreSQLApprovalStore
from apps.audit_service import AuditService
from apps.audit_service.postgres import PostgreSQLAuditStore
from apps.incident_service.repository import IncidentRepository
from apps.runbook_service.executor import RunbookExecutor
from apps.runbook_service.learning import record_runbook_outcome
from apps.runbook_service.runtime_guard import RunbookRuntimeGuard
from apps.runbook_service.registry import RunbookRegistry
from apps.security.auth import require_permission
from database import AsyncSessionLocal
from domain.contracts.logging import logger

router = APIRouter()
_registry = RunbookRegistry()
_executor = RunbookExecutor(_registry)


async def _audit_durable(db, actor: str, incident_id: str, action: str, metadata: Dict[str, Any]) -> None:
    AuditService.record("runbook_execution", actor, incident_id, action, "recorded", metadata)
    await AuditService.flush_to_store(PostgreSQLAuditStore(db), incident_id=incident_id)
    await db.commit()


def _runbook_contract(
    runbook_id: str,
    payload: Dict[str, Any],
    *,
    require_executable: bool = False,
) -> tuple[dict, str, str, str, dict, int, bool]:
    try:
        runbook = _registry.get(runbook_id)
        target = str(payload["target"])
    except KeyError as exc:
        field = exc.args[0]
        if str(field).startswith("Unknown runbook"):
            raise HTTPException(status_code=404, detail="runbook_not_found") from exc
        raise HTTPException(status_code=400, detail=f"missing_field:{field}") from exc

    parameters = dict(payload.get("parameters", {}))
    timeout = int(payload.get("timeout", runbook.get("timeout") or 30))
    rollback = bool(payload.get("rollback", False))
    _registry.validate(runbook_id, parameters)

    execution = (
        dict(runbook.get("execution") or {})
        if isinstance(runbook.get("execution"), dict)
        else {}
    )
    if require_executable and not execution:
        raise HTTPException(
            status_code=409,
            detail="runbook_not_executable",
        )
    if execution:
        tool_name = str(execution.get("tool") or "").strip()
        if not tool_name:
            raise HTTPException(status_code=409, detail="runbook_execution_tool_missing")
        requested_tool = str(payload.get("tool_name") or "").strip()
        if requested_tool and requested_tool != tool_name:
            raise HTTPException(status_code=409, detail="runbook_tool_mismatch")

        if rollback:
            rollback_actions = [
                str(step.get("action") or "").strip()
                for step in runbook.get("rollback", [])
                if isinstance(step, dict)
                and str(step.get("action") or "").strip() not in {"", "none"}
            ]
            requested_action = str(payload.get("action") or "").strip()
            if requested_action not in set(rollback_actions):
                raise HTTPException(status_code=409, detail="runbook_rollback_not_allowed")
            action = requested_action
        else:
            allowed_actions = [
                str(value).strip()
                for value in execution.get("allowed_actions", [])
                if str(value).strip()
            ]
            requested_action = str(payload.get("action") or "").strip()
            if not requested_action and len(allowed_actions) == 1:
                requested_action = allowed_actions[0]
            if not requested_action:
                raise HTTPException(status_code=400, detail="runbook_action_required")
            if requested_action not in set(allowed_actions):
                raise HTTPException(status_code=409, detail="runbook_action_not_allowed")
            action = requested_action
    else:
        try:
            tool_name = str(payload["tool_name"])
        except KeyError as exc:
            raise HTTPException(status_code=400, detail="missing_field:tool_name") from exc
        action = (
            "rollback"
            if rollback
            else str(runbook.get("action") or runbook_id)
        )

    return runbook, tool_name, action, target, parameters, timeout, rollback

@router.post("/runbooks/{runbook_id}/execute")
async def execute_runbook(
    runbook_id: str,
    payload: Dict[str, Any],
    identity=Depends(require_permission("execute:approved")),
):
    runbook, tool_name, action, target, parameters, timeout, rollback = _runbook_contract(
        runbook_id,
        payload,
        require_executable=True,
    )
    approval_id = str(payload.get("approval_id") or "").strip()
    incident_id = str(payload.get("incident_id") or "").strip()
    if not approval_id:
        raise HTTPException(status_code=400, detail="approval_id_required")
    if not incident_id:
        raise HTTPException(status_code=400, detail="incident_id_required")

    version = str(runbook.get("version") or "")
    async with AsyncSessionLocal() as db:
        store = PostgreSQLApprovalStore(db)
        approval = await store.get(approval_id)
        if approval is None:
            raise HTTPException(status_code=404, detail="approval_not_found")
        try:
            assert_bound(
                approval,
                incident_id=incident_id,
                tool_name=tool_name,
                action=action,
                target=target,
                parameters=parameters,
                timeout=timeout,
                runbook_id=runbook_id,
                runbook_version=version,
                rollback=rollback,
            )
        except (TypeError, ValueError) as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc

        execution_contract = (
            dict(runbook.get("execution") or {})
            if isinstance(runbook.get("execution"), dict)
            else {}
        )
        before_snapshot = None
        precondition = None
        if execution_contract:
            before_snapshot = await RunbookRuntimeGuard.collect_snapshot(
                runbook_id=runbook_id,
                target=target,
                parameters=parameters,
                incident_id=incident_id,
                phase="pre",
            )
            precondition = RunbookRuntimeGuard.preflight(
                runbook_id=runbook_id,
                tool_name=tool_name,
                action=action,
                target=target,
                parameters=parameters,
                incident_id=incident_id,
                evidence=list(before_snapshot.get("evidence") or []),
            )
            if not precondition.get("safe_to_execute"):
                revoked = None
                if RunbookRuntimeGuard.approval_should_be_revoked(precondition):
                    revoked = await store.cancel(
                        approval_id,
                        reason="fresh_precondition_invalidated_approved_intent",
                        metadata_patch={
                            "precondition_reason": precondition.get("reason"),
                            "revoked_before_execution": True,
                        },
                    )
                await _audit_durable(
                    db,
                    identity.subject,
                    incident_id,
                    action,
                    {
                        "approval_id": approval_id,
                        "runbook_id": runbook_id,
                        "runbook_version": version,
                        "tool_name": tool_name,
                        "target": target,
                        "phase": "precondition",
                        "precondition": precondition,
                        "snapshot_error": before_snapshot.get("error"),
                        "execution_blocked": True,
                        "approval_revoked": bool(
                            revoked and revoked.get("status") == "rejected"
                        ),
                    },
                )
                raise HTTPException(
                    status_code=409,
                    detail=(
                        "runbook_execution_precondition_failed:"
                        + str(
                            precondition.get("reason")
                            or "runtime_precondition_failed"
                        )
                    ),
                )

        consumed = await store.consume(approval_id)
        if not consumed or consumed.get("status") != "consumed":
            raise HTTPException(status_code=409, detail="approval_already_consumed_or_unavailable")

        result = await _executor.execute(
            runbook_id,
            tool_name=tool_name,
            target=target,
            parameters=parameters,
            action=action,
            timeout=timeout,
            dry_run=False,
            incident_id=incident_id,
            approval_id=approval_id,
            approval_granted=True,
            rollback_requested=rollback,
        )

        verification_payload = None
        verified = None
        execution_payload = (
            dict(result.get("result") or {})
            if isinstance(result.get("result"), dict)
            else {}
        )
        after_snapshot = None
        if execution_contract:
            execution_payload = (
                dict(result.get("result") or {})
                if isinstance(result.get("result"), dict)
                else {}
            )
            execution_success = bool(execution_payload.get("success"))
            if execution_success:
                after_snapshot = await RunbookRuntimeGuard.collect_snapshot(
                    runbook_id=runbook_id,
                    target=target,
                    parameters=parameters,
                    incident_id=incident_id,
                    phase="post",
                )
                verification_result = await RunbookRuntimeGuard.verify(
                    runbook=runbook,
                    action=action,
                    service=str(parameters.get("service") or target),
                    before_context=dict(
                        (before_snapshot or {}).get("context") or {}
                    ),
                    after_context=dict(
                        after_snapshot.get("context") or {}
                    ),
                )
                verification_payload = verification_result.model_dump(
                    mode="json"
                )
                verification_payload["snapshot_error"] = (
                    after_snapshot.get("error")
                )
                verified = (
                    verification_result.status.value == "success"
                    and verification_result.required_objectives_met is True
                )
            else:
                verification_payload = {
                    "status": "failed",
                    "verification_policy": "execution_failed_before_verification",
                    "required_objectives_met": False,
                    "message": (
                        execution_payload.get("error")
                        or execution_payload.get("reason")
                        or "Runbook execution failed before recovery could be verified."
                    ),
                }
                verified = False

            result["precondition"] = precondition
            result["verification"] = verification_payload
            result["verified"] = verified

        memory_id = None
        memory_error = None
        if execution_contract:
            try:
                memory_id = await record_runbook_outcome(
                    db,
                    incident_id=incident_id,
                    runbook=runbook,
                    tool_name=tool_name,
                    action=action,
                    target=target,
                    parameters=parameters,
                    approval=consumed,
                    execution_result=execution_payload,
                    verification_result=dict(verification_payload or {}),
                    before_snapshot=before_snapshot,
                    after_snapshot=after_snapshot,
                )
                if memory_id:
                    result["operational_memory_writeback"] = {
                        "memory_id": memory_id,
                        "verification_status": (
                            verification_payload or {}
                        ).get("status"),
                    }
            except Exception as exc:
                memory_error = type(exc).__name__
                logger.error(
                    "runbook_operational_memory_writeback_failed",
                    incident_id=incident_id,
                    runbook_id=runbook_id,
                    error_type=memory_error,
                )

        incident_status = None
        if verified is not None:
            incidents = IncidentRepository(db)
            incident_status = await incidents.record_operational_outcome(
                incident_id,
                source="runbook_execution",
                action=action,
                target=target,
                approval_id=approval_id,
                execution_success=bool(execution_payload.get("success")),
                verified=bool(verified),
                verification=dict(verification_payload or {}),
                memory_id=memory_id,
            )
            await incidents.commit()
            result["incident_status"] = incident_status

        await _audit_durable(
            db,
            identity.subject,
            incident_id,
            action,
            {
                "approval_id": approval_id,
                "runbook_id": runbook_id,
                "runbook_version": version,
                "tool_name": tool_name,
                "target": target,
                "rollback": rollback,
                "result_status": result.get("status"),
                "verified": verified,
                "verification": verification_payload,
                "precondition": precondition,
                "memory_id": memory_id,
                "memory_error": memory_error,
                "incident_status": incident_status,
            },
        )
        return result


@router.post("/runbooks/{runbook_id}/dry-run")
async def dry_run(
    runbook_id: str,
    payload: Dict[str, Any],
    _identity=Depends(require_permission("read:incident")),
):
    _runbook, tool_name, action, target, parameters, timeout, rollback = _runbook_contract(runbook_id, payload)
    return await _executor.execute(
        runbook_id,
        tool_name=tool_name,
        target=target,
        parameters=parameters,
        action=action,
        timeout=timeout,
        dry_run=True,
        incident_id=None,
        approval_id=None,
        approval_granted=False,
        rollback_requested=rollback,
    )
