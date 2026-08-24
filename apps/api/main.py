from fastapi import FastAPI
from fastapi.responses import FileResponse
from pathlib import Path

from domain.contracts.config import settings
from domain.contracts.logging import configure_logging, logger
from domain.contracts.exceptions import register_exception_handlers

from apps.api import health, workflow, incidents, a2a, execution, e2e_workflow, audit, runbooks, incident_resources, dashboard, runbook_execution, dashboard_incidents, remediation
from agents.triage import TriageAgent
from apps.execution_service.tools.registry import tool_registry
from apps.execution_service.tools.mock_executor import MockExecutorTool
from apps.execution_service.tools.ssh_vm import SSHVMTool
from apps.execution_service.tools.vm_telemetry import VMTelemetryTool
from integrations.vm.ssh_connector import SSHVMConnector
from apps.database.vector_validation import validate_pgvector
from database import AsyncSessionLocal

configure_logging()
app = FastAPI(title=settings.APP_NAME, version=settings.APP_VERSION, debug=settings.DEBUG)
register_exception_handlers(app)

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


@app.get("/")
async def root():
    return {"message": f"Welcome to {settings.APP_NAME}", "version": settings.APP_VERSION, "docs": "/docs", "dashboard": "/dashboard"}


@app.get("/dashboard", include_in_schema=False)
async def dashboard_page():
    return FileResponse(Path(__file__).resolve().parents[2] / "dashboards" / "index.html")


@app.get("/dashboard/", include_in_schema=False)
async def dashboard_page_slash():
    return FileResponse(Path(__file__).resolve().parents[2] / "dashboards" / "index.html")


@app.on_event("startup")
async def startup_event():
    logger.info(f"Starting {settings.APP_NAME} v{settings.APP_VERSION}")
    triage_agent = TriageAgent()
    logger.info(f"Agent registered: {triage_agent.name} - {triage_agent.description}")

    if tool_registry.get_tool("mock_executor") is None:
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
                if not validation.get("extension_installed"):
                    logger.warning("pgvector extension is not installed")
                elif validation.get("dimension_valid") is False:
                    logger.warning("pgvector embedding dimension validation failed")
                else:
                    logger.info(f"pgvector validation: {validation}")
        except Exception as exc:
            logger.warning(f"pgvector validation unavailable: {exc}")
    logger.info(f"Tools available: {tool_registry.list_tools()}")


@app.on_event("shutdown")
async def shutdown_event():
    logger.info(f"Shutting down {settings.APP_NAME}")
