import httpx
from typing import Optional, List, Any
from datetime import datetime, timezone
from integrations.base import BaseConnector, Alert, LogEntry, MetricPoint
from domain.contracts.config import settings
from domain.contracts.logging import logger


class PrometheusClient(BaseConnector):
    """Prometheus client preserving labels needed for deterministic asset identity.

    Empty results represent a successful query with no series. Transport/health
    and Prometheus API failures are propagated so the Evidence layer can record
    `unavailable`/`error` instead of false negative Evidence.
    """

    SERVICE_LABELS = ("service", "service_name", "app")

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

    @staticmethod
    def _parse_time(raw: Any) -> datetime:
        if isinstance(raw, (int, float)):
            return datetime.fromtimestamp(float(raw), tz=timezone.utc)
        if raw:
            try:
                parsed = datetime.fromisoformat(str(raw).replace("Z", "+00:00"))
                return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
            except ValueError:
                pass
        return datetime.now(timezone.utc)

    @staticmethod
    def _escape_label_value(value: str) -> str:
        return str(value).replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")

    @classmethod
    def _metric_queries(cls, metric_name: str, service: Optional[str]) -> List[str]:
        if not service:
            return [metric_name]
        escaped = cls._escape_label_value(service)
        return [f'{metric_name}{{{label}="{escaped}"}}' for label in cls.SERVICE_LABELS]

    @staticmethod
    def _assert_success(payload: Any) -> dict:
        if not isinstance(payload, dict) or payload.get("status") != "success":
            raise RuntimeError("prometheus_api_error")
        return payload

    async def get_alerts(self, since: Optional[datetime] = None, service: Optional[str] = None, limit: int = 100) -> List[Alert]:
        if not await self.health_check():
            raise RuntimeError("prometheus_unavailable")
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            response = await client.get(f"{self._base_url}/api/v1/alerts")
            response.raise_for_status()
            payload = self._assert_success(response.json())
            alerts = []
            for alert in payload.get("data", {}).get("alerts", [])[:limit]:
                labels = alert.get("labels", {}) or {}
                resolved_service = labels.get("service") or labels.get("service_name") or labels.get("app") or service
                alerts.append(Alert(
                    source="prometheus",
                    source_id=str(alert.get("fingerprint", "")),
                    severity=str(labels.get("severity", "unknown")),
                    service=resolved_service,
                    message=str(alert.get("annotations", {}).get("summary", alert.get("message", ""))),
                    timestamp=self._parse_time(alert.get("activeAt")),
                    raw_data=alert,
                ))
            return alerts

    async def get_logs(self, service: str, since: datetime, until: Optional[datetime] = None, level: Optional[str] = None, limit: int = 100) -> List[LogEntry]:
        return []

    async def get_metrics(self, service: str, metric_names: List[str], since: datetime, until: Optional[datetime] = None) -> List[MetricPoint]:
        if not await self.health_check():
            raise RuntimeError("prometheus_unavailable")
        start_ts = int(since.timestamp())
        end_ts = int(until.timestamp()) if until else int(datetime.now(timezone.utc).timestamp())
        metrics: List[MetricPoint] = []
        seen: set[tuple[str, tuple[tuple[str, str], ...], float]] = set()
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            for metric_name in metric_names:
                for query in self._metric_queries(metric_name, service):
                    response = await client.get(
                        f"{self._base_url}/api/v1/query_range",
                        params={"query": query, "start": start_ts, "end": end_ts, "step": "60"},
                    )
                    response.raise_for_status()
                    payload = self._assert_success(response.json())
                    for result in payload.get("data", {}).get("result", []):
                        labels = {str(k): str(v) for k, v in (result.get("metric", {}) or {}).items()}
                        resolved_service = labels.get("service") or labels.get("service_name") or labels.get("app") or service
                        label_key = tuple(sorted(labels.items()))
                        for ts, value in result.get("values", []):
                            try:
                                numeric_value = float(value)
                                timestamp_value = float(ts)
                            except (TypeError, ValueError):
                                continue
                            key = (metric_name, label_key, timestamp_value)
                            if key in seen:
                                continue
                            seen.add(key)
                            metrics.append(MetricPoint(
                                timestamp=self._parse_time(ts),
                                service=resolved_service,
                                name=metric_name,
                                value=numeric_value,
                                labels=labels,
                                source="prometheus",
                            ))
        return metrics
