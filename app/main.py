from fastapi import FastAPI

from app.core.config import settings
from app.core.logging import configure_logging, logger
from app.core.exceptions import register_exception_handlers

from app.api import health
from app.api import workflow
from app.api import incidents
from app.api import a2a

from app.agents.triage_agent import TriageAgent

from app.tools.registry import tool_registry
from app.tools.mock_executor import MockExecutorTool


# ================================================================
# Logging
# ================================================================

configure_logging()


# ================================================================
# Application
# ================================================================

app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    debug=settings.DEBUG,
)


# ================================================================
# Exception handlers
# ================================================================

register_exception_handlers(app)


# ================================================================
# Routers
# ================================================================

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


# ================================================================
# Root
# ================================================================

@app.get("/")
async def root():

    return {
        "message": (
            f"Welcome to "
            f"{settings.APP_NAME}"
        ),
        "version": settings.APP_VERSION,
        "docs": "/docs",
    }


# ================================================================
# Startup
# ================================================================

@app.on_event("startup")
async def startup_event():

    logger.info(
        f"Starting "
        f"{settings.APP_NAME} "
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

    # ------------------------------------------------------------
    # Register Agents
    # ------------------------------------------------------------

    triage_agent = TriageAgent()

    logger.info(
        f"Agent registered: "
        f"{triage_agent.name} - "
        f"{triage_agent.description}"
    )

    # ------------------------------------------------------------
    # Register Development Tools
    # ------------------------------------------------------------

    mock_executor = MockExecutorTool()

    tool_registry.register(
        mock_executor
    )

    logger.info(
        "Development tool registered: "
        "mock_executor"
    )

    # ------------------------------------------------------------
    # Registry state
    # ------------------------------------------------------------

    logger.info(
        f"Tools available: "
        f"{tool_registry.list_tools()}"
    )


# ================================================================
# Shutdown
# ================================================================

@app.on_event("shutdown")
async def shutdown_event():

    logger.info(
        f"Shutting down "
        f"{settings.APP_NAME}"
    )