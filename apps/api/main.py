from fastapi import Depends, FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pathlib import Path
from urllib.parse import urlparse

from domain.contracts.config import settings
from domain.contracts.logging import configure_logging, logger
from domain.contracts.exceptions import register_exception_handlers
from domain.contracts.rate_limit import rate_limiter_strict

from apps.api import health, workflow, incidents, a2a, execution, e2e_workflow, audit, runbooks, incident_resources, dashboard, runbook_execution, dashboard_incidents, remediation, agents, signals
from apps.execution_service.tools.registry import tool_registry
from apps.execution_service.tools.mock_executor import MockExecutorTool
from apps.execution_service.tools.ssh_vm import SSHVMTool
from apps.execution_service.tools.vm_telemetry import VMTelemetryTool
from integrations.vm.mcp_client import VMEdgeMCPClient
from apps.database.vector_validation import validate_pgvector
from database import AsyncSessionLocal
from apps.security.auth import require_permission

configure_logging()
app = FastAPI(title=settings.APP_NAME, version=settings.APP_VERSION, debug=settings.DEBUG)
register_exception_handlers(app)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=False,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "X-API-Key"],
)

for router, tags in [
    (health.router, ["Health"]),
    (workflow.router, ["Workflow"]),
    (e2e_workflow.router, ["E2E Workflow"]),
    (audit.router, ["Audit"]),
    (runbooks.router, ["Runbooks"]),
    (runbook_execution.router, ["Runbook Execution"]),
    (incident_resources.router, ["Incident Resources"]),
    (incidents.router, ["Incidents"]),
    (signals.router, ["Signals"]),
    (remediation.router, ["Remediation"]),
    (a2a.router, ["A2A"]),
    (execution.router, ["Execution"]),
    (dashboard.router, ["Dashboard"]),
    (dashboard_incidents.router, ["Dashboard Incidents"]),
    (agents.router, ["Agents"]),
]:
    app.include_router(router, prefix="/api/v1", tags=tags)

_MASTER_API_ROUTES = {
    "/api/v1/health": (health.health_check, ["GET"], []),
    "/api/v1/incidents/analyze": (incidents.analyze_incident, ["POST"], [Depends(rate_limiter_strict), Depends(require_permission("read:incident"))]),
    "/api/v1/dashboard/summary": (dashboard.dashboard_summary, ["GET"], [Depends(require_permission("read:incident"))]),
    "/api/v1/approvals": (execution.create_approval, ["POST"], [Depends(require_permission("approve:low_risk"))]),
    "/api/v1/runbooks/{runbook_id}/execute": (runbook_execution.execute_runbook, ["POST"], [Depends(require_permission("execute:approved"))]),
    "/api/v1/runbooks/{runbook_id}/dry-run": (runbook_execution.dry_run, ["POST"], [Depends(require_permission("read:incident"))]),
}
for _path, (_endpoint, _methods, _dependencies) in _MASTER_API_ROUTES.items():
    if not any(getattr(route, "path", None) == _path for route in app.routes):
        app.add_api_route(_path, _endpoint, methods=_methods, dependencies=_dependencies)

_DASHBOARD_DIR = Path(__file__).resolve().parents[2] / "dashboards"


@app.get("/")
async def root():
    return {
        "message": f"Welcome to {settings.APP_NAME}",
        "version": settings.APP_VERSION,
        "docs": "/docs",
        "dashboard": "/dashboard",
        "agent_dashboard": "/dashboard/agents",
    }


@app.get("/dashboard", include_in_schema=False)
async def dashboard_page():
    return FileResponse(_DASHBOARD_DIR / "index.html")


@app.get("/dashboard/", include_in_schema=False)
async def dashboard_page_slash():
    return FileResponse(_DASHBOARD_DIR / "index.html")


@app.get("/dashboard/agents", include_in_schema=False)
async def agent_dashboard_page():
    return FileResponse(_DASHBOARD_DIR / "index.html")


@app.get("/dashboard/control-center.css", include_in_schema=False)
async def dashboard_stylesheet():
    return FileResponse(_DASHBOARD_DIR / "control-center.css", media_type="text/css")


@app.get("/dashboard/control-center.js", include_in_schema=False)
async def dashboard_script():
    return FileResponse(_DASHBOARD_DIR / "control-center.js", media_type="application/javascript")


def _validate_production_configuration() -> None:
    if settings.APP_ENV != "production":
        return
    errors = []
    if "*" in settings.CORS_ORIGINS:
        errors.append("CORS_ORIGINS wildcard is forbidden in production")
    oidc_ready = all((settings.OIDC_ISSUER_URL, settings.OIDC_AUDIENCE, settings.OIDC_JWKS_URL))
    if not oidc_ready and not settings.INTERNAL_API_KEY:
        errors.append("production requires OIDC or INTERNAL_API_KEY authentication")
    if settings.LLM_PROVIDER.strip().lower() == "mock":
        errors.append("mock LLM provider is forbidden in production")
    if settings.EMBEDDING_PROVIDER.strip().lower() == "deterministic":
        errors.append("deterministic embedding provider is forbidden in production")
    if settings.DATABASE_URL and "user:password@" in settings.DATABASE_URL:
        errors.append("default database credentials are forbidden in production")

    required_mcp = {
        "ZABBIX_MCP_URL": settings.ZABBIX_MCP_URL,
        "ELASTICSEARCH_MCP_URL": settings.ELASTICSEARCH_MCP_URL,
        "PROMETHEUS_MCP_URL": settings.PROMETHEUS_MCP_URL,
    }
    for name, value in required_mcp.items():
        if not str(value or "").strip():
            errors.append(f"{name} is required in production")
        elif urlparse(str(value)).scheme != "https":
            errors.append(f"{name} must use HTTPS in production")
    if not settings.MCP_REQUIRE_HTTPS:
        errors.append("MCP_REQUIRE_HTTPS must be enabled in production")
    if not settings.MCP_BEARER_TOKEN and not (settings.MCP_CLIENT_CERT_PATH and settings.MCP_CLIENT_KEY_PATH):
        errors.append("production MCP requires bearer identity or mTLS client certificate")
    if bool(settings.MCP_CLIENT_CERT_PATH) != bool(settings.MCP_CLIENT_KEY_PATH):
        errors.append("MCP client certificate and key must be configured together")
    if settings.SSH_ENABLED:
        errors.append("direct Control-Plane SSH is forbidden; configure VM_MCP_URL instead")
    if settings.KUBERNETES_API_URL:
        errors.append("direct Control-Plane Kubernetes API access is forbidden; configure KUBERNETES_MCP_URL instead")

    if settings.APPROVAL_TTL_SECONDS <= 0:
        errors.append("APPROVAL_TTL_SECONDS must be positive in production")
    if settings.AGENT_MAX_PARALLELISM <= 0 or settings.AGENT_MAX_EVIDENCE_ROUNDS <= 0:
        errors.append("agent routing limits must be positive")
    if settings.AGENT_MAX_DYNAMIC_EVIDENCE_TYPES <= 0:
        errors.append("AGENT_MAX_DYNAMIC_EVIDENCE_TYPES must be positive")
    if settings.AGENT_TIMEOUT_SECONDS <= 0 or settings.A2A_TIMEOUT_SECONDS <= 0:
        errors.append("agent/A2A timeouts must be positive")
    for name, value in {
        "AGENT_MIN_EVIDENCE_COVERAGE": settings.AGENT_MIN_EVIDENCE_COVERAGE,
        "AGENT_LOW_CONFIDENCE_THRESHOLD": settings.AGENT_LOW_CONFIDENCE_THRESHOLD,
        "AGENT_MIN_CONSENSUS_SCORE": settings.AGENT_MIN_CONSENSUS_SCORE,
        "AGENT_DISAGREEMENT_CONFIDENCE_FACTOR": settings.AGENT_DISAGREEMENT_CONFIDENCE_FACTOR,
        "AGENT_MISSING_EVIDENCE_CONFIDENCE_FACTOR": settings.AGENT_MISSING_EVIDENCE_CONFIDENCE_FACTOR,
        "AGENT_CONFLICT_CONFIDENCE_PENALTY": settings.AGENT_CONFLICT_CONFIDENCE_PENALTY,
    }.items():
        if not 0 <= value <= 1:
            errors.append(f"{name} must be between 0 and 1")
    if not settings.AGENT_SOURCE_QUALITY_WEIGHTS:
        errors.append("AGENT_SOURCE_QUALITY_WEIGHTS must not be empty")
    elif any(not 0 <= float(value) <= 1 for value in settings.AGENT_SOURCE_QUALITY_WEIGHTS.values()):
        errors.append("AGENT_SOURCE_QUALITY_WEIGHTS values must be between 0 and 1")
    if not settings.AGENT_ENABLED_AGENTS:
        errors.append("at least one specialist agent must be enabled")
    if settings.A2A_ALLOWED_TARGETS and not settings.A2A_REQUIRE_HTTPS:
        errors.append("production A2A targets require HTTPS")
    if errors:
        raise RuntimeError("production_configuration_invalid: " + "; ".join(errors))


@app.on_event("startup")
async def startup_event():
    logger.info(f"Starting {settings.APP_NAME} v{settings.APP_VERSION}")
    _validate_production_configuration()

    if settings.APP_ENV != "production" and tool_registry.get_tool("mock_executor") is None:
        tool_registry.register(MockExecutorTool())

    if settings.VM_MCP_URL:
        vm_connector = VMEdgeMCPClient()
        if tool_registry.get_tool("ssh_vm") is None:
            tool_registry.register(SSHVMTool(vm_connector))
            logger.info("Governed VM MCP execution tool registered")
        if tool_registry.get_tool("vm_telemetry") is None:
            tool_registry.register(VMTelemetryTool(vm_connector))
            logger.info("Read-only VM MCP telemetry tool registered")

    if settings.PGVECTOR_VALIDATE_ON_STARTUP:
        try:
            async with AsyncSessionLocal() as db:
                validation = await validate_pgvector(db, settings.PGVECTOR_EXPECTED_DIMENSION)
            valid = validation.get("extension_installed") and validation.get("dimension_valid") is not False
            if not valid:
                message = f"pgvector startup validation failed: {validation}"
                if settings.APP_ENV == "production":
                    raise RuntimeError(message)
                logger.warning(message)
            else:
                logger.info(f"pgvector validation: {validation}")
        except Exception as exc:
            if settings.APP_ENV == "production":
                logger.error(f"Production startup blocked by pgvector validation: {exc}")
                raise
            logger.warning(f"pgvector validation unavailable: {exc}")
    logger.info(f"Tools available: {tool_registry.list_tools()}")


@app.on_event("shutdown")
async def shutdown_event():
    logger.info(f"Shutting down {settings.APP_NAME}")
