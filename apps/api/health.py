from __future__ import annotations

import asyncio
from datetime import datetime, timezone

from fastapi import APIRouter, Response, status
from sqlalchemy import text

from apps.execution_service.tools.registry import tool_registry
from database import AsyncSessionLocal, check_pgvector_ready
from domain.contracts.config import settings
from domain.contracts.logging import logger
from integrations.elasticsearch.mcp_client import ElasticsearchMCPClient
from integrations.prometheus.mcp_client import PrometheusMCPClient
from integrations.zabbix.mcp_client import ZabbixMCPClient

router = APIRouter()


async def _probe_database() -> dict:
    try:
        async with AsyncSessionLocal() as db:
            await db.execute(text("SELECT 1"))
        vector = await check_pgvector_ready()
        if not vector.get("pgvector_available"):
            return {"status": "unhealthy", "error": "pgvector_unavailable"}
        return {"status": "healthy", "pgvector": {"available": True}}
    except Exception as exc:
        logger.warning("database_health_probe_failed", error_type=type(exc).__name__)
        return {"status": "unhealthy", "error": "database_unavailable"}


async def _probe_external() -> dict:
    connectors = {
        "zabbix_mcp": ZabbixMCPClient(),
        "elasticsearch_mcp": ElasticsearchMCPClient(),
        "prometheus_mcp": PrometheusMCPClient(),
    }
    try:
        values = await asyncio.wait_for(
            asyncio.gather(*(client.health_check() for client in connectors.values())),
            timeout=min(float(settings.MCP_TIMEOUT_SECONDS) + 1.0, 15.0),
        )
        return {name: {"healthy": bool(value)} for name, value in zip(connectors, values)}
    except Exception as exc:
        logger.warning("external_health_probe_failed", error_type=type(exc).__name__)
        return {name: {"healthy": False, "error": "dependency_unavailable"} for name in connectors}
    finally:
        await asyncio.gather(*(client.close() for client in connectors.values()), return_exceptions=True)


def _external_ready(external: dict) -> bool:
    return bool(external) and all(bool(component.get("healthy")) for component in external.values())


@router.get("/health")
async def health_check():
    logger.info("Health check requested")
    database = await _probe_database()
    external = await _probe_external()
    database_healthy = database["status"] == "healthy"
    external_healthy = _external_ready(external)
    healthy = database_healthy and (external_healthy if settings.APP_ENV == "production" else True)
    return {
        "status": "ok" if healthy else "degraded",
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
async def readiness(response: Response):
    database = await _probe_database()
    external = await _probe_external()
    database_ready = database["status"] == "healthy"
    external_ready = _external_ready(external)
    ready = database_ready and (external_ready if settings.APP_ENV == "production" else True)
    if not ready:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    return {
        "status": "ready" if ready else "not_ready",
        "database": database,
        "external": external,
    }
