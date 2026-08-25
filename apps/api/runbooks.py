from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Dict

import yaml
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from apps.security.auth import require_permission
from apps.runbook_service.registry import RunbookRegistry
from domain.runbook_validation import validate_runbook

router = APIRouter()
registry = RunbookRegistry()


class RunbookCreateRequest(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    owner: str = Field(min_length=1, max_length=255)
    version: str = Field(min_length=1, max_length=50)
    risk_level: str = Field(min_length=1, max_length=32)
    preconditions: list[Any] = Field(default_factory=list)
    steps: list[Any] = Field(min_length=1)
    timeout: int = Field(default=300, ge=1, le=3600)
    rollback: list[Any] = Field(default_factory=list)
    enabled: bool = True


def _safe_filename(name: str) -> str:
    value = re.sub(r"[^a-zA-Z0-9._-]+", "_", name.strip())
    value = value.strip("._")
    if not value:
        raise HTTPException(status_code=400, detail="invalid_runbook_name")
    return value + ".yml"


@router.get("/runbooks")
async def list_runbooks(_user=Depends(require_permission("read:incident"))):
    return {"items": registry.list()}


@router.post("/runbooks", status_code=201)
async def create_runbook(
    payload: RunbookCreateRequest,
    _user=Depends(require_permission("manage:runbook")),
):
    data: Dict[str, Any] = payload.model_dump()
    validation = validate_runbook(data)
    if not validation["valid"]:
        raise HTTPException(status_code=422, detail=validation)

    root = registry.root
    root.mkdir(parents=True, exist_ok=True)
    path = root / _safe_filename(payload.name)
    if path.exists():
        raise HTTPException(status_code=409, detail="runbook_already_exists")
    path.write_text(yaml.safe_dump(data, sort_keys=False, allow_unicode=True), encoding="utf-8")
    registry.load()
    return {"name": payload.name, "status": "created", "path": str(path)}


@router.get("/runbooks/{name}")
async def get_runbook(name: str, _user=Depends(require_permission("read:incident"))):
    try:
        return registry.get(name)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.post("/runbooks/{name}/dry-run")
async def dry_run(name: str, _user=Depends(require_permission("read:incident"))):
    try:
        return registry.dry_run(name)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc