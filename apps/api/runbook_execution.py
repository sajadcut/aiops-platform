from __future__ import annotations

from typing import Any, Dict

from fastapi import APIRouter, Depends, HTTPException

from apps.security.auth import require_permission
from apps.runbook_service.executor import RunbookExecutor
from apps.runbook_service.registry import RunbookRegistry

router = APIRouter()
_registry = RunbookRegistry()
_executor = RunbookExecutor(_registry)


@router.post("/runbooks/{runbook_id}/execute")
async def execute_runbook(runbook_id: str, payload: Dict[str, Any], _user=Depends(require_permission("execute:approved"))):
    try:
        return await _executor.execute(
            runbook_id,
            tool_name=str(payload["tool_name"]),
            target=str(payload["target"]),
            parameters=dict(payload.get("parameters", {})),
            timeout=int(payload.get("timeout", 30)),
            dry_run=bool(payload.get("dry_run", False)),
            approval_id=payload.get("approval_id"),
            rollback_requested=bool(payload.get("rollback", False)),
        )
    except KeyError as exc:
        raise HTTPException(status_code=400, detail=f"missing_field:{exc.args[0]}")
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@router.post("/runbooks/{runbook_id}/dry-run")
async def dry_run(runbook_id: str, payload: Dict[str, Any], _user=Depends(require_permission("read:incident"))):
    payload["dry_run"] = True
    payload.pop("approval_id", None)
    return await execute_runbook(runbook_id, payload, _user)
