import httpx
from typing import Optional, List
from datetime import datetime
from integrations.base import BaseConnector, Alert, LogEntry, MetricPoint
from domain.contracts.config import settings
from domain.contracts.logging import logger


class PrometheusClient(BaseConnector):
    """Client for Prometheus; endpoint and timeout are centrally configured."""

    def __init__(self, url: Optional[str] = None, timeout: Optional[int] = None):
        self.url = url or settings.PROMETHEUS_URL
        self.timeout = timeout if timeout is not None else settings.PROMETHEUS_TIMEOUT_SECONDS

    @property
    def source_name(self) -> str:
        return "prometheus"

    @property
    def _base_url(self) -> str:
        return self.url.rstrip("/")

    async def health_check(self) -> bool:
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.get(f"{self._base_url}/-/healthy")
                return response.status_code == 200
        except Exception as exc:
            logger.warning(f"Prometheus health check failed: {exc}")
            return False

    async def get_alerts(self, since: Optional[datetime] = None, service: Optional[str] = None, limit: int = 100) -> List[Alert]:
        try:
            if not await self.health_check():
                return []
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.get(f"{self._base_url}/api/v1/alerts")
                if response.status_code != 200:
                    return []
                alerts = []
                for alert in response.json().get("data", {}).get("alerts", [])[:limit]:
                    labels = alert.get("labels", {})
                    alerts.append(
                        Alert(
                            source="prometheus",
                            source_id=alert.get("fingerprint", ""),
                            severity=labels.get("severity", "unknown"),
                            service=labels.get("service", service),
                            message=alert.get("annotations", {}).get("summary", alert.get("message", "")),
                            timestamp=datetime.fromtimestamp(alert.get("activeAt", 0)),
                            raw_data=alert,
                        )
                    )
                return alerts
        except Exception as exc:
            logger.error(f"Failed to get Prometheus alerts: {exc}")
            return []

    async def get_logs(self, service: str, since: datetime, until: Optional[datetime] = None, level: Optional[str] = None, limit: int = 100) -> List[LogEntry]:
        return []

    async def get_metrics(self, service: str, metric_names: List[str], since: datetime, until: Optional[datetime] = None) -> List[MetricPoint]:
        try:
            if not await self.health_check():
                return []
            start_ts = int(since.timestamp())
            end_ts = int(until.timestamp()) if until else int(datetime.now().timestamp())
            metrics = []
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                for metric_name in metric_names:
                    query = f'{metric_name}{{service="{service}"}}' if service else metric_name
                    response = await client.get(
                        f"{self._base_url}/api/v1/query_range",
                        params={"query": query, "start": start_ts, "end": end_ts, "step": "60"},
                    )
                    if response.status_code != 200:
                        continue
                    for result in response.json().get("data", {}).get("result", []):
                        labels = result.get("metric", {})
                        for ts, value in result.get("values", []):
                            metrics.append(
                                MetricPoint(
                                    timestamp=datetime.fromtimestamp(ts),
                                    service=service,
                                    name=metric_name,
                                    value=float(value) if isinstance(value, (int, float)) else 0.0,
                                    labels=labels,
                                    source="prometheus",
                                )
                            )
            return metrics
        except Exception as exc:
            logger.error(f"Failed to get Prometheus metrics: {exc}")
            return []
