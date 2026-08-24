from typing import Any, Dict, List
from datetime import datetime


class EvidenceCollector:
    """Combines live evidence sources; live evidence remains authoritative."""

    def __init__(self, zabbix=None, elasticsearch=None, prometheus=None):
        self.zabbix = zabbix
        self.elasticsearch = elasticsearch
        self.prometheus = prometheus

    async def collect(self, service: str, since: datetime, until: datetime | None = None) -> Dict[str, Any]:
        alerts: List[Any] = []
        logs: List[Any] = []
        metrics: List[Any] = []
        if self.zabbix:
            alerts = await self.zabbix.get_alerts(since=since, service=service)
        if self.elasticsearch:
            logs = await self.elasticsearch.get_logs(service, since, until)
        if self.prometheus:
            metrics = await self.prometheus.get_metrics(service, ["up", "rate(http_requests_total[5m])"], since, until)
        evidence = []
        for item in alerts:
            evidence.append({"type": "alert", "source": "zabbix", "reference": getattr(item, "source_id", None), "raw_data": getattr(item, "raw_data", {})})
        for item in logs:
            evidence.append({"type": "log", "source": "elasticsearch", "reference": f"log:{getattr(item, 'timestamp', '')}", "raw_data": getattr(item, "raw_data", {})})
        for item in metrics:
            evidence.append({"type": "metric", "source": "prometheus", "reference": f"metric:{getattr(item, 'name', '')}:{getattr(item, 'timestamp', '')}", "raw_data": {"value": getattr(item, "value", None), "name": getattr(item, "name", None)}})
        return {"service": service, "since": since.isoformat(), "until": until.isoformat() if until else None, "evidence": evidence}
