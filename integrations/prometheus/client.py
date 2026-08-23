import httpx
from typing import Optional, List
from datetime import datetime, timedelta
import json
from integrations.base import BaseConnector, Alert, LogEntry, MetricPoint
from domain.contracts.config import settings
from domain.contracts.logging import logger

class PrometheusClient(BaseConnector):
    """
    Client برای دریافت متریک‌ها از Prometheus
    با قابلیت Fallback در صورت عدم دسترسی
    """
    
    def __init__(
        self,
        url: Optional[str] = None,
        timeout: int = 10
    ):
        self.url = url or getattr(settings, "PROMETHEUS_URL", "http://localhost:9090")
        self.timeout = timeout
    
    @property
    def source_name(self) -> str:
        return "prometheus"
    
    async def health_check(self) -> bool:
        """بررسی در دسترس بودن Prometheus"""
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.get(f"{self.url}/-/healthy")
                return response.status_code == 200
        except Exception as e:
            logger.warning(f"Prometheus health check failed: {str(e)}")
            return False
    
    async def get_alerts(self, since: Optional[datetime] = None, service: Optional[str] = None, limit: int = 100) -> List[Alert]:
        """دریافت Alertهای فعال از AlertManager (در MVP ساده)"""
        try:
            if not await self.health_check():
                return []
            
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.get(f"{self.url}/api/v1/alerts")
                if response.status_code != 200:
                    return []
                
                data = response.json()
                alerts = []
                for alert in data.get("data", {}).get("alerts", [])[:limit]:
                    labels = alert.get("labels", {})
                    alerts.append(Alert(
                        source="prometheus",
                        source_id=alert.get("fingerprint", ""),
                        severity=labels.get("severity", "unknown"),
                        service=labels.get("service", service),
                        message=alert.get("annotations", {}).get("summary", alert.get("message", "")),
                        timestamp=datetime.fromtimestamp(alert.get("activeAt", 0)),
                        raw_data=alert
                    ))
                
                return alerts
                
        except Exception as e:
            logger.error(f"Failed to get Prometheus alerts: {str(e)}")
            return []
    
    async def get_logs(self, service: str, since: datetime, until: Optional[datetime] = None, level: Optional[str] = None, limit: int = 100) -> List[LogEntry]:
        """Prometheus لاگ ندارد (خالی)"""
        return []
    
    async def get_metrics(
        self,
        service: str,
        metric_names: List[str],
        since: datetime,
        until: Optional[datetime] = None
    ) -> List[MetricPoint]:
        """دریافت متریک‌های یک سرویس از Prometheus"""
        try:
            if not await self.health_check():
                logger.warning("Prometheus not available, returning empty metrics")
                return []
            
            start_ts = int(since.timestamp())
            end_ts = int(until.timestamp()) if until else int(datetime.now().timestamp())
            
            metrics = []
            for metric_name in metric_names:
                # ✅ خط اصلاح شده - از {{ و }} برای فرار دادن آکولادها استفاده شده
                query = f'{metric_name}{{service="{service}"}}' if service else metric_name
                
                async with httpx.AsyncClient(timeout=self.timeout) as client:
                    response = await client.get(
                        f"{self.url}/api/v1/query_range",
                        params={
                            "query": query,
                            "start": start_ts,
                            "end": end_ts,
                            "step": "60"
                        }
                    )
                    
                    if response.status_code != 200:
                        continue
                    
                    data = response.json()
                    for result in data.get("data", {}).get("result", []):
                        metric_labels = result.get("metric", {})
                        values = result.get("values", [])
                        
                        for ts, value in values:
                            metrics.append(MetricPoint(
                                timestamp=datetime.fromtimestamp(ts),
                                service=service,
                                name=metric_name,
                                value=float(value) if isinstance(value, (int, float)) else 0.0,
                                labels=metric_labels,
                                source="prometheus"
                            ))
            
            logger.info(f"Retrieved {len(metrics)} metrics from Prometheus for service {service}")
            return metrics
            
        except Exception as e:
            logger.error(f"Failed to get Prometheus metrics: {str(e)}")
            return []