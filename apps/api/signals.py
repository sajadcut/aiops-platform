from __future__ import annotations

from typing import Any, Dict, List

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from apps.security.auth import require_permission
from apps.signal_gateway import (
    OperationalSignal,
    SignalGateway,
    signal_from_elasticsearch,
    signal_from_prometheus,
    signal_from_zabbix,
)
from database import AsyncSessionLocal
from domain.contracts.rate_limit import rate_limiter_strict


router = APIRouter()


class RawSignalPayload(BaseModel):
    payload: Dict[str, Any] = Field(default_factory=dict)


async def _ingest(signal: OperationalSignal) -> Dict[str, Any]:
    try:
        async with AsyncSessionLocal() as db:
            result = await SignalGateway.ingest(db, signal)
        return {
            "status": "accepted",
            "incident_id": result.get("incident_id"),
            "trigger_source": result.get("trigger_source"),
            "trigger_signal_type": result.get("trigger_signal_type"),
            "correlation_key": result.get("correlation_key"),
            "deduplicated": bool(result.get("deduplicated", False)),
            "deduplication_reason": result.get("deduplication_reason"),
            "asset_context": (result.get("context") or {}).get("asset_context"),
            "routing": result.get("routing"),
            "coordination": result.get("coordination"),
            "evaluation": result.get("evaluation"),
            "decision": result.get("decision"),
            "terminal_reason": result.get("terminal_reason"),
        }
    except Exception as exc:
        raise HTTPException(status_code=500, detail="signal_ingestion_failed") from exc


@router.post("/signals/ingest", dependencies=[Depends(rate_limiter_strict)])
async def ingest_signal(
    request: Request,
    signal: OperationalSignal,
    _user=Depends(require_permission("ingest:signal")),
):
    return await _ingest(signal)


@router.post("/signals/elasticsearch", dependencies=[Depends(rate_limiter_strict)])
async def ingest_elasticsearch_signal(
    request: Request,
    body: RawSignalPayload,
    _user=Depends(require_permission("ingest:signal")),
):
    return await _ingest(signal_from_elasticsearch(body.payload))


@router.post("/signals/prometheus", dependencies=[Depends(rate_limiter_strict)])
async def ingest_prometheus_signal(
    request: Request,
    body: RawSignalPayload,
    _user=Depends(require_permission("ingest:signal")),
):
    payload = body.payload
    alerts: List[Dict[str, Any]] = payload.get("alerts", []) if isinstance(payload.get("alerts"), list) else []
    if not alerts:
        return await _ingest(signal_from_prometheus(payload))
    results = []
    for alert in alerts:
        if isinstance(alert, dict):
            results.append(await _ingest(signal_from_prometheus(alert)))
    return {
        "status": "accepted",
        "count": len(results),
        "deduplicated_count": sum(1 for item in results if item.get("deduplicated")),
        "results": results,
    }


@router.post("/signals/zabbix", dependencies=[Depends(rate_limiter_strict)])
async def ingest_zabbix_signal(
    request: Request,
    body: RawSignalPayload,
    _user=Depends(require_permission("ingest:signal")),
):
    return await _ingest(signal_from_zabbix(body.payload))
