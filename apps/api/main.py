from fastapi import Depends, FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pathlib import Path

from domain.contracts.config import settings
from domain.contracts.logging import configure_logging, logger
from domain.contracts.exceptions import register_exception_handlers
from domain.contracts.rate_limit import rate_limiter_strict

from apps.api import health, workflow, incidents, a2a, execution, e2e_workflow, audit, runbooks, incident_resources, dashboard, runbook_execution, dashboard_incidents, remediation
from apps.execution_service.tools.registry import tool_registry
from apps.execution_service.tools.mock_executor import MockExecutorTool
from apps.execution_service.tools.ssh_vm import SSHVMTool
from apps.execution_service.tools.vm_telemetry import VMTelemetryTool
from integrations.vm.ssh_connector import SSHVMConnector
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
    (remediation.router, ["Remediation"]),
    (a2a.router, ["A2A"]),
    (execution.router, ["Execution"]),
    (dashboard.router, ["Dashboard"]),
    (dashboard_incidents.router, ["Dashboard Incidents"]),
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


@app.get("/")
async def root():
    return {"message": f"Welcome to {settings.APP_NAME}", "version": settings.APP_VERSION, "docs": "/docs", "dashboard": "/dashboard"}


@app.get("/dashboard", include_in_schema=False)
async def dashboard_page():
    return FileResponse(Path(__file__).resolve().parents[2] / "dashboards" / "index.html")


@app.get("/dashboard/", include_in_schema=False)
async def dashboard_page_slash():
    return FileResponse(Path(__file__).resolve().parents[2] / "dashboards" / "index.html")


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
    if settings.SSH_ENABLED and not settings.SSH_STRICT_HOST_KEY_CHECKING:
        errors.append("SSH strict host key checking must be enabled in production")
    if settings.APPROVAL_TTL_SECONDS <= 0:
        errors.append("APPROVAL_TTL_SECONDS must be positive in production")
    if errors:
        raise RuntimeError("production_configuration_invalid: " + "; ".join(errors))


@app.on_event("startup")
async def startup_event():
    logger.info(f"Starting {settings.APP_NAME} v{settings.APP_VERSION}")
    _validate_production_configuration()

    if settings.APP_ENV != "production" and tool_registry.get_tool("mock_executor") is None:
        tool_registry.register(MockExecutorTool())

    if settings.SSH_ENABLED:
        vm_connector = SSHVMConnector()
        if tool_registry.get_tool("ssh_vm") is None:
            tool_registry.register(SSHVMTool(vm_connector))
            logger.info("Governed SSH VM tool registered")
        if tool_registry.get_tool("vm_telemetry") is None:
            tool_registry.register(VMTelemetryTool(vm_connector))
            logger.info("Read-only VM telemetry tool registered")

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
