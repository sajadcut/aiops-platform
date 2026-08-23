import httpx
from typing import Optional, List
from datetime import datetime
import json
from integrations.base import BaseConnector, Alert, LogEntry, MetricPoint
from domain.contracts.config import settings
from domain.contracts.logging import logger

class ElasticsearchClient(BaseConnector):
    """
    Client برای جستجو در Elasticsearch
    با قابلیت Fallback در صورت عدم دسترسی
    """
    
    def __init__(
        self,
        hosts: Optional[List[str]] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
        timeout: int = 10
    ):
        self.hosts = hosts or getattr(settings, "ELASTICSEARCH_HOSTS", ["http://localhost:9200"])
        self.username = username or getattr(settings, "ELASTICSEARCH_USERNAME", "")
        self.password = password or getattr(settings, "ELASTICSEARCH_PASSWORD", "")
        self.timeout = timeout
        self._auth = None
        if self.username and self.password:
            self._auth = (self.username, self.password)
    
    @property
    def source_name(self) -> str:
        return "elasticsearch"
    
    async def health_check(self) -> bool:
        """بررسی در دسترس بودن Elasticsearch"""
        try:
            async with httpx.AsyncClient(timeout=self.timeout, auth=self._auth) as client:
                response = await client.get(f"{self.hosts[0]}/_cluster/health")
                return response.status_code == 200
        except Exception as e:
            logger.warning(f"Elasticsearch health check failed: {str(e)}")
            return False
    
    async def get_alerts(self, since: Optional[datetime] = None, service: Optional[str] = None, limit: int = 100) -> List[Alert]:
        """Elasticsearch به‌عنوان منبع Alert استفاده نمی‌شود (خالی)"""
        return []
    
    async def get_logs(
        self,
        service: str,
        since: datetime,
        until: Optional[datetime] = None,
        level: Optional[str] = None,
        limit: int = 100
    ) -> List[LogEntry]:
        """جستجوی لاگ‌های یک سرویس در بازه زمانی مشخص"""
        try:
            if not await self.health_check():
                logger.warning("Elasticsearch not available, returning empty logs")
                return []
            
            # ساخت query برای Elasticsearch
            must_conditions = [
                {"match": {"service": service}},
                {"range": {"@timestamp": {"gte": since.isoformat()}}}
            ]
            
            if until:
                must_conditions.append({"range": {"@timestamp": {"lte": until.isoformat()}}})
            
            if level:
                must_conditions.append({"match": {"level": level}})
            
            query = {
                "query": {
                    "bool": {
                        "must": must_conditions
                    }
                },
                "sort": [{"@timestamp": {"order": "desc"}}],
                "size": limit
            }
            
            async with httpx.AsyncClient(timeout=self.timeout, auth=self._auth) as client:
                response = await client.post(
                    f"{self.hosts[0]}/_search",
                    json=query
                )
                
                if response.status_code != 200:
                    logger.error(f"Elasticsearch query failed: {response.text}")
                    return []
                
                data = response.json()
                logs = []
                for hit in data.get("hits", {}).get("hits", []):
                    source = hit.get("_source", {})
                    logs.append(LogEntry(
                        timestamp=datetime.fromisoformat(source.get("@timestamp", "").replace("Z", "+00:00")),
                        service=source.get("service", service),
                        level=source.get("level", "info"),
                        message=source.get("message", ""),
                        source="elasticsearch",
                        raw_data=source
                    ))
                
                logger.info(f"Retrieved {len(logs)} logs from Elasticsearch for service {service}")
                return logs
                
        except Exception as e:
            logger.error(f"Failed to get Elasticsearch logs: {str(e)}")
            return []  # Fallback
    
    async def get_metrics(self, service: str, metric_names: List[str], since: datetime, until: Optional[datetime] = None) -> List[MetricPoint]:
        """Elasticsearch معمولاً برای متریک استفاده نمی‌شود (خالی)"""
        return []