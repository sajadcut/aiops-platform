from __future__ import annotations

from typing import Any, Dict

from fastapi import APIRouter, Depends, HTTPException

from apps.approval_service.postgres import PostgreSQLApprovalStore
from apps.security.auth import require_permission
from apps.runbook_service.executor import RunbookExecutor
from apps.runbook_service.registry import RunbookRegistry
from database import AsyncSessionLocal

router = APIRouter()
_registry = RunbookRegistry()
_executor = RunbookExecutor(_registry)


async def _approval_state(approval_id: str | None) -> bool:
    if not approval_id:
        return False
    async with AsyncSessionLocal() as db:
        record = await PostgreSQLApprovalStore(db).get(str(approval_id))
    return bool(record and record.get("status") == "approved")


@router.post("/runbooks/{runbook_id}/execute")
async def execute_runbook(
    runbook_id: str,
    payload: Dict[str, Any],
    _user=Depends(require_permission("execute:approved")),
):
    try:
        approval_id = payload.get("approval_id")
        approved = await _approval_state(approval_id)
        if not approved:
            raise HTTPException(status_code=409, detail="approved_approval_id_required")
        return await _executor.execute(
            runbook_id,
            tool_name=str(payload["tool_name"]),
            target=str(payload["target"]),
            parameters=dict(payload.get("parameters", {})),
            timeout=int(payload.get("timeout", 30)),
            dry_run=bool(payload.get("dry_run", False)),
            approval_id=approval_id,
            approval_granted=True,
            incident_id=payload.get("incident_id"),
            rollback_requested=bool(payload.get("rollback", False)),
        )
    except KeyError as exc:
        raise HTTPException(status_code=400, detail=f"missing_field:{exc.args[0]}") from exc
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.post("/runbooks/{runbook_id}/dry-run")
async def dry_run(
    runbook_id: str,
    payload: Dict[str, Any],
    _user=Depends(require_permission("read:incident")),
):
    payload = dict(payload)
    payload["dry_run"] = True
    payload.pop("approval_id", None)
    # Dry-run must never require or consume an approval.
    try:
        return await _executor.execute(
            runbook_id,
            tool_name=str(payload["tool_name"]),
            target=str(payload["target"]),
            parameters=dict(payload.get("parameters", {})),
            timeout=int(payload.get("timeout", 30)),
            dry_run=True,
            incident_id=payload.get("incident_id"),
            rollback_requested=False,
        )
    except KeyError as exc:
        raise HTTPException(status_code=400, detail=f"missing_field:{exc.args[0]}") from exc
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
