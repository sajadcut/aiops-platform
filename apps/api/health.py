from __future__ import annotations

import asyncio
from datetime import datetime, timezone

from fastapi import APIRouter
from fastapi.responses import JSONResponse
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
        return {"status": "healthy", "pgvector": vector}
    except Exception as exc:
        return {"status": "unhealthy", "error": str(exc)}


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
        return {name: {"healthy": False, "error": type(exc).__name__} for name in connectors}
    finally:
        await asyncio.gather(*(client.close() for client in connectors.values()), return_exceptions=True)


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
    body = {"status": "ready" if ready else "not_ready", "database": database, "external": external}
    if not ready:
        # Kubernetes HTTP probes only use the status code. Returning 200 with a
        # "not_ready" body incorrectly admits traffic to an unhealthy replica.
        return JSONResponse(status_code=503, content=body)
    return body
