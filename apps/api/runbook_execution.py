from __future__ import annotations

from typing import Any, Dict

from fastapi import APIRouter, Depends, HTTPException

from apps.approval_service.binding import assert_bound
from apps.approval_service.postgres import PostgreSQLApprovalStore
from apps.audit_service import AuditService
from apps.audit_service.postgres import PostgreSQLAuditStore
from apps.runbook_service.executor import RunbookExecutor
from apps.runbook_service.registry import RunbookRegistry
from apps.security.auth import require_permission
from database import AsyncSessionLocal

router = APIRouter()
_registry = RunbookRegistry()
_executor = RunbookExecutor(_registry)


async def _audit_durable(db, actor: str, incident_id: str, action: str, metadata: Dict[str, Any]) -> None:
    AuditService.record("runbook_execution", actor, incident_id, action, "recorded", metadata)
    await AuditService.flush_to_store(PostgreSQLAuditStore(db), incident_id=incident_id)
    await db.commit()


def _runbook_contract(runbook_id: str, payload: Dict[str, Any]) -> tuple[dict, str, str, dict, int, bool]:
    try:
        runbook = _registry.get(runbook_id)
        tool_name = str(payload["tool_name"])
        target = str(payload["target"])
    except KeyError as exc:
        field = exc.args[0]
        if str(field).startswith("Unknown runbook"):
            raise HTTPException(status_code=404, detail="runbook_not_found") from exc
        raise HTTPException(status_code=400, detail=f"missing_field:{field}") from exc
    parameters = dict(payload.get("parameters", {}))
    timeout = int(payload.get("timeout", 30))
    rollback = bool(payload.get("rollback", False))
    _registry.validate(runbook_id, parameters)
    return runbook, tool_name, target, parameters, timeout, rollback


@router.post("/runbooks/{runbook_id}/execute")
async def execute_runbook(
    runbook_id: str,
    payload: Dict[str, Any],
    identity=Depends(require_permission("execute:approved")),
):
    runbook, tool_name, target, parameters, timeout, rollback = _runbook_contract(runbook_id, payload)
    approval_id = str(payload.get("approval_id") or "").strip()
    incident_id = str(payload.get("incident_id") or "").strip()
    if not approval_id:
        raise HTTPException(status_code=400, detail="approval_id_required")
    if not incident_id:
        raise HTTPException(status_code=400, detail="incident_id_required")

    action = "rollback" if rollback else str(runbook.get("action") or runbook_id)
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

        consumed = await store.consume(approval_id)
        if not consumed or consumed.get("status") != "consumed":
            raise HTTPException(status_code=409, detail="approval_already_consumed_or_unavailable")

        result = await _executor.execute(
            runbook_id,
            tool_name=tool_name,
            target=target,
            parameters=parameters,
            timeout=timeout,
            dry_run=False,
            approval_id=approval_id,
            approval_granted=True,
            rollback_requested=rollback,
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
                "rollback": rollback,
                "result_status": result.get("status"),
            },
        )
        return result


@router.post("/runbooks/{runbook_id}/dry-run")
async def dry_run(
    runbook_id: str,
    payload: Dict[str, Any],
    _identity=Depends(require_permission("read:incident")),
):
    _runbook, tool_name, target, parameters, timeout, rollback = _runbook_contract(runbook_id, payload)
    return await _executor.execute(
        runbook_id,
        tool_name=tool_name,
        target=target,
        parameters=parameters,
        timeout=timeout,
        dry_run=True,
        approval_id=None,
        approval_granted=False,
        rollback_requested=rollback,
    )
