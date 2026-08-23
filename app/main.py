from fastapi import FastAPI
from app.core.config import settings
from app.core.logging import configure_logging, logger
from app.api import health, workflow, incidents
from app.agents.triage_agent import TriageAgent
from app.tools.registry import tool_registry
from app.core.exceptions import register_exception_handlers

# پیکربندی لاگینگ
configure_logging()

# ایجاد اپلیکیشن
app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    debug=settings.DEBUG,
)

# ثبت هندلرهای خطا
register_exception_handlers(app)

# ثبت routerها
app.include_router(health.router, prefix="/api/v1", tags=["Health"])
app.include_router(workflow.router, prefix="/api/v1", tags=["Workflow"])
app.include_router(incidents.router, prefix="/api/v1", tags=["Incidents"])
# در بخش ثبت routerها اضافه کنید
from app.api import a2a
app.include_router(a2a.router, prefix="/api/v1", tags=["A2A"])

@app.get("/")
async def root():
    logger.info("Root endpoint called")
    return {
        "message": f"Welcome to {settings.APP_NAME}",
        "version": settings.APP_VERSION,
        "docs": "/docs"
    }

@app.on_event("startup")
async def startup_event():
    logger.info(f"Starting {settings.APP_NAME} v{settings.APP_VERSION}")
    logger.info(f"LLM Provider: {settings.LLM_PROVIDER}")
    logger.info(f"Log Level: {settings.LOG_LEVEL}")
    
    triage_agent = TriageAgent()
    logger.info(f"Agent registered: {triage_agent.name} - {triage_agent.description}")
    logger.info(f"Tools available: {tool_registry.list_tools()}")

@app.on_event("shutdown")
async def shutdown_event():
    logger.info("Shutting down application")