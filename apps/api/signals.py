from __future__ import annotations

from typing import Any, Dict, List

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from apps.security.auth import require_permission
from apps.signal_gateway import OperationalSignal, SignalGateway, signal_from_elasticsearch, signal_from_prometheus
from apps.signal_gateway.elastic_anomaly import ElasticAnomalyWebhookPayload, ingest_elastic_anomaly_payload
from apps.signal_gateway.zabbix_lifecycle import ingest_zabbix_payload
from database import AsyncSessionLocal
from database.migration_validation import validate_migration_head
from domain.contracts.config import settings
from domain.contracts.logging import logger
from domain.contracts.rate_limit import rate_limiter_strict
from integrations.vm.target_context import bind_vm_port, bind_vm_target, reset_vm_port, reset_vm_target, target_from_zabbix_payload, target_port_from_zabbix_payload

router = APIRouter()


class RawSignalPayload(BaseModel):
    payload: Dict[str, Any] = Field(default_factory=dict)


def _response_from_result(result: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "status": result.get("status") or "accepted",
        "incident_id": result.get("incident_id"),
        "trigger_source": result.get("trigger_source"),
        "trigger_signal_type": result.get("trigger_signal_type"),
        "correlation_key": result.get("correlation_key"),
        "deduplicated": bool(result.get("deduplicated", False)),
        "deduplication_reason": result.get("deduplication_reason"),
        "signal_state": result.get("signal_state"),
        "recovered": result.get("recovered"),
        "recovery_unmatched": result.get("recovery_unmatched"),
        "recovery_of_source_id": result.get("recovery_of_source_id"),
        "incident_status": result.get("incident_status"),
        "approval_cancellations": result.get("approval_cancellations"),
        "asset_context": (result.get("context") or {}).get("asset_context"),
        "routing": result.get("routing"),
        "coordination": result.get("coordination"),
        "evaluation": result.get("evaluation"),
        "remediation_plan": result.get("remediation_plan"),
        "decision": result.get("decision"),
        "approval": result.get("approval"),
        "execution_result": result.get("execution_result"),
        "verification_result": result.get("verification_result"),
        "terminal_reason": result.get("terminal_reason"),
        "ignored": bool(result.get("ignored", False)),
        "anomaly_score": result.get("anomaly_score"),
        "elastic_job_ids": result.get("elastic_job_ids"),
    }


async def _require_database_ready(db) -> None:
    """Reject new workflows before expensive analysis when DB schema is stale.

    Startup already validates Alembic state, but development mode intentionally
    logs drift instead of refusing to boot. Signal ingestion is a write path and
    must fail fast rather than run a long RCA only to fail while persisting an
    approval/checkpoint at the end of the workflow.
    """
    if not settings.DATABASE_VALIDATE_MIGRATIONS_ON_STARTUP:
        return
    migration = await validate_migration_head(db)
    if migration.get("valid"):
        return
    logger.error("signal_ingestion_blocked_by_migration_drift", migration=migration)
    raise HTTPException(
        status_code=503,
        detail={
            "code": "DATABASE_MIGRATION_DRIFT",
            "message": "Database schema is not at the repository Alembic head",
            "expected_heads": migration.get("expected_heads", []),
            "current_heads": migration.get("current_heads", []),
            "error": migration.get("error"),
        },
    )


async def _ingest(signal: OperationalSignal) -> Dict[str, Any]:
    try:
        async with AsyncSessionLocal() as db:
            await _require_database_ready(db)
            result = await SignalGateway.ingest(db, signal)
        return _response_from_result(result)
    except HTTPException:
        raise
    except Exception as exc:
        logger.exception("signal_ingestion_failed", source=signal.source, error_type=type(exc).__name__)
        raise HTTPException(status_code=500, detail="signal_ingestion_failed") from exc


async def _ingest_elastic_anomaly(payload: Dict[str, Any]) -> Dict[str, Any]:
    try:
        async with AsyncSessionLocal() as db:
            await _require_database_ready(db)
            result = await ingest_elastic_anomaly_payload(db, payload)
        return _response_from_result(result)
    except HTTPException:
        raise
    except Exception as exc:
        logger.exception("signal_ingestion_failed", source="elasticsearch", signal_kind="ml_anomaly", error_type=type(exc).__name__)
        raise HTTPException(status_code=500, detail="signal_ingestion_failed") from exc


async def _ingest_zabbix(payload: Dict[str, Any]) -> Dict[str, Any]:
    target_token = bind_vm_target(target_from_zabbix_payload(payload))
    port_token = bind_vm_port(target_port_from_zabbix_payload(payload))
    try:
        async with AsyncSessionLocal() as db:
            await _require_database_ready(db)
            result = await ingest_zabbix_payload(db, payload)
        return _response_from_result(result)
    except HTTPException:
        raise
    except Exception as exc:
        logger.exception("signal_ingestion_failed", source="zabbix", error_type=type(exc).__name__)
        raise HTTPException(status_code=500, detail="signal_ingestion_failed") from exc
    finally:
        reset_vm_port(port_token)
        reset_vm_target(target_token)


@router.post("/signals/ingest", dependencies=[Depends(rate_limiter_strict)])
async def ingest_signal(request: Request, signal: OperationalSignal, _user=Depends(require_permission("ingest:signal"))):
    return await _ingest(signal)


@router.post("/signals/elasticsearch", dependencies=[Depends(rate_limiter_strict)])
async def ingest_elasticsearch_signal(request: Request, body: RawSignalPayload, _user=Depends(require_permission("ingest:signal"))):
    return await _ingest(signal_from_elasticsearch(body.payload))


@router.post("/signals/elasticsearch/anomaly", dependencies=[Depends(rate_limiter_strict)])
async def ingest_elasticsearch_anomaly(
    request: Request,
    body: ElasticAnomalyWebhookPayload,
    _user=Depends(require_permission("ingest:signal")),
):
    return await _ingest_elastic_anomaly(body.model_dump(mode="json"))


@router.post("/signals/prometheus", dependencies=[Depends(rate_limiter_strict)])
async def ingest_prometheus_signal(request: Request, body: RawSignalPayload, _user=Depends(require_permission("ingest:signal"))):
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
async def ingest_zabbix_signal(request: Request, body: RawSignalPayload, _user=Depends(require_permission("ingest:signal"))):
    return await _ingest_zabbix(body.payload)
