from fastapi import FastAPI

from domain.contracts.config import settings
from domain.contracts.logging import configure_logging, logger
from domain.contracts.exceptions import register_exception_handlers

from apps.api import health, workflow, incidents, a2a, execution, e2e_workflow, audit, runbooks
from agents.triage import TriageAgent
from apps.execution_service.tools.registry import tool_registry
from apps.execution_service.tools.mock_executor import MockExecutorTool

configure_logging()

app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    debug=settings.DEBUG,
)

register_exception_handlers(app)

app.include_router(health.router, prefix="/api/v1", tags=["Health"])
app.include_router(workflow.router, prefix="/api/v1", tags=["Workflow"])
app.include_router(e2e_workflow.router, prefix="/api/v1", tags=["E2E Workflow"])
app.include_router(audit.router, prefix="/api/v1", tags=["Audit"])
app.include_router(runbooks.router, prefix="/api/v1", tags=["Runbooks"])
app.include_router(incidents.router, prefix="/api/v1", tags=["Incidents"])
app.include_router(a2a.router, prefix="/api/v1", tags=["A2A"])
app.include_router(execution.router, prefix="/api/v1", tags=["Execution"])


@app.get("/")
async def root():
    return {"message": f"Welcome to {settings.APP_NAME}", "version": settings.APP_VERSION, "docs": "/docs"}


@app.on_event("startup")
async def startup_event():
    logger.info(f"Starting {settings.APP_NAME} v{settings.APP_VERSION}")
    logger.info(f"LLM Provider: {settings.LLM_PROVIDER}")
    logger.info(f"Log Level: {settings.LOG_LEVEL}")

    triage_agent = TriageAgent()
    logger.info(f"Agent registered: {triage_agent.name} - {triage_agent.description}")

    if tool_registry.get_tool("mock_executor") is None:
        tool_registry.register(MockExecutorTool())

    logger.info(f"Tools available: {tool_registry.list_tools()}")


@app.on_event("shutdown")
async def shutdown_event():
    logger.info(f"Shutting down {settings.APP_NAME}")
