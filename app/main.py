# ============================================================
# FILE: app/main.py
# ============================================================

from fastapi import FastAPI

from app.core.config import settings
from app.core.logging import configure_logging, logger
from app.core.exceptions import register_exception_handlers

from app.api import (
    health,
    workflow,
    incidents,
    a2a,
    execution,
)

from app.agents.triage_agent import TriageAgent

from app.tools.registry import tool_registry
from app.tools.mock_executor import MockExecutorTool


configure_logging()


app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    debug=settings.DEBUG,
)


register_exception_handlers(app)


app.include_router(
    health.router,
    prefix="/api/v1",
    tags=["Health"],
)

app.include_router(
    workflow.router,
    prefix="/api/v1",
    tags=["Workflow"],
)

app.include_router(
    incidents.router,
    prefix="/api/v1",
    tags=["Incidents"],
)

app.include_router(
    a2a.router,
    prefix="/api/v1",
    tags=["A2A"],
)

app.include_router(
    execution.router,
    prefix="/api/v1",
    tags=["Execution"],
)


@app.get("/")
async def root():

    return {
        "message": (
            f"Welcome to {settings.APP_NAME}"
        ),
        "version": settings.APP_VERSION,
        "docs": "/docs",
    }


@app.on_event("startup")
async def startup_event():

    logger.info(
        f"Starting {settings.APP_NAME} "
        f"v{settings.APP_VERSION}"
    )

    logger.info(
        f"LLM Provider: "
        f"{settings.LLM_PROVIDER}"
    )

    logger.info(
        f"Log Level: "
        f"{settings.LOG_LEVEL}"
    )

    triage_agent = TriageAgent()

    logger.info(
        f"Agent registered: "
        f"{triage_agent.name} - "
        f"{triage_agent.description}"
    )

    if tool_registry.get_tool(
        "mock_executor"
    ) is None:

        tool_registry.register(
            MockExecutorTool()
        )

    logger.info(
        f"Tools available: "
        f"{tool_registry.list_tools()}"
    )


@app.on_event("shutdown")
async def shutdown_event():

    logger.info(
        f"Shutting down {settings.APP_NAME}"
    )