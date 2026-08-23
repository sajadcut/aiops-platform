from fastapi import APIRouter
from app.core.config import settings
from app.core.logging import logger
from app.infrastructure.database import check_pgvector_ready
from app.llm.mock_provider import MockLLMProvider
from app.tools.registry import tool_registry
from app.integrations.zabbix.connector import ZabbixConnector
from app.integrations.elasticsearch.client import ElasticsearchClient
from app.integrations.prometheus.client import PrometheusClient
import asyncio

router = APIRouter()

@router.get("/health")
async def health_check():
    """
    بررسی سلامت کامل سرویس و همه کامپوننت‌ها.
    """
    logger.info("Health check requested")
    
    # ۱. دیتابیس
    db_status = await check_pgvector_ready()
    
    # ۲. LLM
    try:
        llm = MockLLMProvider()
        test_response = await llm.generate("test", max_tokens=5)
        llm_status = {"status": "healthy", "provider": llm.provider_name}
    except Exception as e:
        llm_status = {"status": "unhealthy", "error": str(e)}
    
    # ۳. ابزارها
    tools_status = {
        "total": len(tool_registry._tools),
        "available": tool_registry.list_tools()
    }
    
    # ۴. منابع خارجی
    zabbix = ZabbixConnector()
    elastic = ElasticsearchClient()
    prometheus = PrometheusClient()
    
    zabbix_task = asyncio.create_task(zabbix.health_check())
    elastic_task = asyncio.create_task(elastic.health_check())
    prometheus_task = asyncio.create_task(prometheus.health_check())
    
    try:
        zabbix_health, elastic_health, prometheus_health = await asyncio.wait_for(
            asyncio.gather(zabbix_task, elastic_task, prometheus_task),
            timeout=5.0
        )
    except asyncio.TimeoutError:
        zabbix_health = elastic_health = prometheus_health = False
        logger.warning("Health check timeout for external services")
    
    return {
        "status": "ok",
        "service": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "timestamp": __import__("datetime").datetime.now().isoformat(),
        "components": {
            "database": db_status,
            "llm": llm_status,
            "tools": tools_status,
            "external": {
                "zabbix": {"healthy": zabbix_health},
                "elasticsearch": {"healthy": elastic_health},
                "prometheus": {"healthy": prometheus_health}
            }
        }
    }