from __future__ import annotations

import asyncio
from datetime import datetime, timezone

from fastapi import APIRouter
from fastapi.responses import JSONResponse, Response
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest
from sqlalchemy import text

from apps.execution_service.tools.registry import tool_registry
from database import AsyncSessionLocal, check_pgvector_ready, engine
from database.migration_validation import validate_migration_head
from domain.contracts.config import settings
from domain.contracts.logging import logger
from domain.observability import DB_POOL_CHECKED_OUT, DB_POOL_OVERFLOW, DB_POOL_SIZE, DEPENDENCY_UP
from integrations.cognia import CogniaClient
from integrations.elasticsearch.mcp_client import ElasticsearchMCPClient
from integrations.jenkins.mcp_client import JenkinsMCPClient
from integrations.kubernetes.mcp_client import KubernetesMCPClient
from integrations.prometheus.mcp_client import PrometheusMCPClient
from integrations.vm.mcp_client import VMEdgeMCPClient
from integrations.zabbix.mcp_client import ZabbixMCPClient

router = APIRouter()


def _pool_status() -> dict:
    pool = engine.sync_engine.pool
    result = {"class": type(pool).__name__}
    for key, method_name in {
        "size": "size",
        "checked_out": "checkedout",
        "overflow": "overflow",
    }.items():
        method = getattr(pool, method_name, None)
        if callable(method):
            try:
                result[key] = int(method())
            except Exception:
                result[key] = None
    if isinstance(result.get("size"), int):
        DB_POOL_SIZE.set(result["size"])
    if isinstance(result.get("checked_out"), int):
        DB_POOL_CHECKED_OUT.set(result["checked_out"])
    if isinstance(result.get("overflow"), int):
        DB_POOL_OVERFLOW.set(result["overflow"])
    return result


async def _probe_database() -> dict:
    try:
        async with AsyncSessionLocal() as db:
            await db.execute(text("SELECT 1"))
            migration = await validate_migration_head(db)
        vector = await check_pgvector_ready()
        healthy = bool(
            vector.get("db_connected")
            and vector.get("pgvector_available")
            and (migration.get("valid") or not settings.DATABASE_VALIDATE_MIGRATIONS_ON_STARTUP)
        )
        DEPENDENCY_UP.labels(dependency="postgresql").set(1 if healthy else 0)
        return {
            "status": "healthy" if healthy else "unhealthy",
            "pgvector": {
                "available": bool(vector.get("pgvector_available")),
                "error": vector.get("error"),
            },
            "migration": migration,
            "pool": _pool_status(),
        }
    except Exception as exc:
        logger.exception("database_health_probe_failed")
        DEPENDENCY_UP.labels(dependency="postgresql").set(0)
        return {"status": "unhealthy", "error": type(exc).__name__, "pool": _pool_status()}


async def _probe_one(name: str, client) -> tuple[str, dict]:
    timeout = (
        float(settings.COGNIA_TIMEOUT_SECONDS) + 1.0
        if name == "cognia"
        else float(settings.MCP_TIMEOUT_SECONDS) + 1.0
    )
    # Read retry is valuable for evidence collection but harmful for readiness:
    # Kubernetes and dashboards probe health repeatedly, so retrying every
    # unavailable MCP multiple times creates retry amplification and slow health
    # responses. Limit only MCP health clients to one transport attempt; normal
    # operational clients retain the configured bounded retry policy.
    if name != "cognia" and hasattr(client, "read_retry_attempts_override"):
        client.read_retry_attempts_override = 1
    try:
        value = await asyncio.wait_for(client.health_check(), timeout=min(timeout, 30.0))
        healthy = bool(value)
        DEPENDENCY_UP.labels(dependency=name).set(1 if healthy else 0)
        return name, {"healthy": healthy}
    except Exception as exc:
        logger.warning("dependency_health_probe_failed", dependency=name, error_type=type(exc).__name__)
        DEPENDENCY_UP.labels(dependency=name).set(0)
        return name, {"healthy": False, "error": type(exc).__name__}
    finally:
        await client.close()


async def _probe_external() -> dict:
    connectors = {
        "zabbix_mcp": ZabbixMCPClient(),
        "elasticsearch_mcp": ElasticsearchMCPClient(),
        "prometheus_mcp": PrometheusMCPClient(),
    }
    static: dict = {}
    if settings.JENKINS_MCP_URL:
        connectors["jenkins_mcp"] = JenkinsMCPClient()
    if settings.KUBERNETES_MCP_URL:
        connectors["kubernetes_mcp"] = KubernetesMCPClient()
    if settings.VM_MCP_URL:
        connectors["vm_mcp"] = VMEdgeMCPClient()
    if settings.COGNIA_BASE_URL:
        try:
            connectors["cognia"] = CogniaClient()
        except Exception as exc:
            static["cognia"] = {"healthy": False, "configured": False, "error": type(exc).__name__}
            DEPENDENCY_UP.labels(dependency="cognia").set(0)
    else:
        static["cognia"] = {"healthy": False, "configured": False, "error": "not_configured"}
        DEPENDENCY_UP.labels(dependency="cognia").set(0)
    pairs = await asyncio.gather(*(_probe_one(name, client) for name, client in connectors.items()))
    return {**dict(pairs), **static}


def _external_required_ready(external: dict) -> bool:
    if settings.APP_ENV != "production":
        return True
    required = ["zabbix_mcp", "elasticsearch_mcp", "prometheus_mcp"]
    if settings.JENKINS_MCP_URL:
        required.append("jenkins_mcp")
    if settings.KUBERNETES_MCP_URL:
        required.append("kubernetes_mcp")
    if settings.VM_MCP_URL:
        required.append("vm_mcp")
    required.append("cognia")
    return all(bool((external.get(name) or {}).get("healthy")) for name in required)


@router.get("/health")
async def health_check():
    database, external = await asyncio.gather(_probe_database(), _probe_external())
    ready = database["status"] == "healthy" and _external_required_ready(external)
    return {
        "status": "ok" if ready else "degraded",
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
    database, external = await asyncio.gather(_probe_database(), _probe_external())
    ready = database["status"] == "healthy" and _external_required_ready(external)
    payload = {"status": "ready" if ready else "not_ready", "database": database, "external": external}
    if ready:
        return payload
    return JSONResponse(status_code=503, content=payload)


@router.get("/metrics", include_in_schema=False)
async def metrics():
    return Response(content=generate_latest(), media_type=CONTENT_TYPE_LATEST)
