from fastapi import APIRouter, Depends, HTTPException

from apps.runbook_service.registry import RunbookRegistry
from apps.security.auth import require_permission

router = APIRouter(dependencies=[Depends(require_permission("read:incident"))])
registry = RunbookRegistry()


@router.get("/runbooks")
async def list_runbooks():
    return {"items": registry.list()}


@router.get("/runbooks/{name}")
async def get_runbook(name: str):
    try:
        return registry.get(name)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.post("/runbooks/{name}/dry-run")
async def dry_run(name: str):
    """Validate a runbook without crossing the real execution boundary."""
    try:
        return registry.dry_run(name)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
