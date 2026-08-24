import httpx
from typing import Optional, List, Dict, Any
from datetime import datetime, timezone
from integrations.base import BaseConnector, Alert, LogEntry, MetricPoint
from domain.contracts.config import settings
from domain.contracts.logging import logger


class ElasticsearchClient(BaseConnector):
    """Production connector for operational log evidence.

    All hosts, credentials and timeout values come from the centralized Settings object.
    """

    def __init__(
        self,
        hosts: Optional[List[str]] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
        timeout: Optional[int] = None,
    ):
        self.hosts = hosts if hosts is not None else settings.ELASTICSEARCH_HOSTS
        self.username = username if username is not None else settings.ELASTICSEARCH_USERNAME
        self.password = password if password is not None else settings.ELASTICSEARCH_PASSWORD
        self.timeout = timeout if timeout is not None else settings.ELASTICSEARCH_TIMEOUT_SECONDS
        self._auth = (self.username, self.password) if self.username and self.password else None

    @property
    def source_name(self) -> str:
        return "elasticsearch"

    @property
    def _base_url(self) -> str:
        if not self.hosts:
            raise RuntimeError("ELASTICSEARCH_HOSTS must contain at least one URL")
        return self.hosts[0].rstrip("/")

    async def health_check(self) -> bool:
        try:
            async with httpx.AsyncClient(timeout=self.timeout, auth=self._auth) as client:
                response = await client.get(f"{self._base_url}/_cluster/health")
                return response.status_code == 200
        except Exception as exc:
            logger.warning(f"Elasticsearch health check failed: {exc}")
            return False

    async def get_alerts(self, since: Optional[datetime] = None, service: Optional[str] = None, limit: int = 100) -> List[Alert]:
        return []

    async def search_logs(self, query: str, start: Optional[str] = None, end: Optional[str] = None, limit: int = 100) -> List[Dict[str, Any]]:
        if not await self.health_check():
            return []
        filters = []
        if start or end:
            filters.append({"range": {"@timestamp": {k: v for k, v in (("gte", start), ("lte", end)) if v}}})
        body = {
            "query": {"bool": {"must": [{"query_string": {"query": query}}], "filter": filters}},
            "size": limit,
        }
        try:
            async with httpx.AsyncClient(timeout=self.timeout, auth=self._auth) as client:
                response = await client.post(f"{self._base_url}/_search", json=body)
                response.raise_for_status()
                return [
                    {"id": h.get("_id"), "reference": h.get("_id"), "source": "elasticsearch", "type": "log", "raw_data": h.get("_source", {})}
                    for h in response.json().get("hits", {}).get("hits", [])
                ]
        except Exception as exc:
            logger.error(f"Elasticsearch search failed: {exc}")
            return []

    async def get_logs(self, service: str, since: datetime, until: Optional[datetime] = None, level: Optional[str] = None, limit: int = 100) -> List[LogEntry]:
        rows = await self.search_logs(
            f'service:"{service}"' + (f' level:"{level}"' if level else ""),
            since.isoformat(),
            until.isoformat() if until else None,
            limit,
        )
        result = []
        for row in rows:
            src = row.get("raw_data", {})
            timestamp = datetime.now(timezone.utc)
            raw = src.get("@timestamp")
            if raw:
                try:
                    timestamp = datetime.fromisoformat(str(raw).replace("Z", "+00:00"))
                except ValueError:
                    pass
            result.append(
                LogEntry(
                    timestamp=timestamp,
                    service=src.get("service", service),
                    level=src.get("level", "info"),
                    message=str(src.get("message", "")),
                    source="elasticsearch",
                    raw_data=src,
                )
            )
        return result

    async def get_metrics(self, service: str, metric_names: List[str], since: datetime, until: Optional[datetime] = None) -> List[MetricPoint]:
        return []
