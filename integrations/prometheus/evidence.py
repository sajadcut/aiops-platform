from __future__ import annotations
from datetime import datetime
from typing import Any, Dict, List
from .client import PrometheusClient

class PrometheusEvidenceAdapter:
    def __init__(self, client: PrometheusClient):
        self.client = client

    async def collect(self, service: str, metrics: List[str], start: datetime, end: datetime) -> List[Dict[str, Any]]:
        points = await self.client.get_metrics(service, metrics, start, end)
        return [
            {"id": f"prom:{p.name}:{p.timestamp.isoformat()}", "type": "metric", "source": "prometheus",
             "reference": f"{p.name}@{p.timestamp.isoformat()}", "confidence": 1.0,
             "raw_data": {"name": p.name, "value": p.value, "labels": p.labels}}
            for p in points
        ]
