from __future__ import annotations

import asyncio
from datetime import datetime, timezone

from fastapi import APIRouter
from sqlalchemy import text

from apps.execution_service.tools.registry import tool_registry
from database import AsyncSessionLocal, check_pgvector_ready
from domain.contracts.config import settings
from domain.contracts.logging import logger
from integrations.elasticsearch.client import ElasticsearchClient
from integrations.prometheus.client import PrometheusClient
from integrations.zabbix.connector import ZabbixConnector

router = APIRouter()


async def _probe_database() -> dict:
    try:
        async with AsyncSessionLocal() as db:
            await db.execute(text("SELECT 1"))
        vector = await check_pgvector_ready()
        return {"status": "healthy", "pgvector": vector}
    except Exception as exc:
        return {"status": "unhealthy", "error": str(exc)}


async def _probe_external() -> dict:
    probes = {
        "zabbix": ZabbixConnector().health_check(),
        "elasticsearch": ElasticsearchClient().health_check(),
        "prometheus": PrometheusClient().health_check(),
    }
    try:
        values = await asyncio.wait_for(asyncio.gather(*probes.values()), timeout=5.0)
        return {name: {"healthy": bool(value)} for name, value in zip(probes, values)}
    except Exception as exc:
        return {name: {"healthy": False, "error": str(exc)} for name in probes}


@router.get("/health")
async def health_check():
    logger.info("Health check requested")
    database = await _probe_database()
    external = await _probe_external()
    status = "ok" if database["status"] == "healthy" else "degraded"
    return {
        "status": status,
        "service": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "components": {
            "database": database,
            "tools": {"total": len(tool_registry.list_tools()), "available": tool_registry.list_tools()},
            "external": external,
        },
    }


@router.get("/health/live")
async def liveness():
    return {"status": "alive", "service": settings.APP_NAME}


@router.get("/health/ready")
async def readiness():
    database = await _probe_database()
    external = await _probe_external()
    ready = database["status"] == "healthy"
    return {"status": "ready" if ready else "not_ready", "database": database, "external": external}
