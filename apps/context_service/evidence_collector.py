from typing import Any, Dict, List
from datetime import datetime


class EvidenceCollector:
    """Combines live operational evidence; live evidence remains authoritative."""

    def __init__(self, zabbix=None, elasticsearch=None, prometheus=None, vm=None):
        self.zabbix = zabbix
        self.elasticsearch = elasticsearch
        self.prometheus = prometheus
        self.vm = vm

    async def collect(self, service: str, since: datetime, until: datetime | None = None) -> Dict[str, Any]:
        alerts: List[Any] = []
        logs: List[Any] = []
        metrics: List[Any] = []
        evidence = []

        if self.zabbix:
            alerts = await self.zabbix.get_alerts(since=since, service=service)
        if self.elasticsearch:
            logs = await self.elasticsearch.get_logs(service, since, until)
        if self.prometheus:
            metrics = await self.prometheus.get_metrics(service, ["up", "rate(http_requests_total[5m])"], since, until)

        for item in alerts:
            evidence.append({"type": "alert", "source": "zabbix", "reference": getattr(item, "source_id", None), "raw_data": getattr(item, "raw_data", {})})
        for item in logs:
            evidence.append({"type": "log", "source": "elasticsearch", "reference": f"log:{getattr(item, 'timestamp', '')}", "raw_data": getattr(item, "raw_data", {})})
        for item in metrics:
            evidence.append({"type": "metric", "source": "prometheus", "reference": f"metric:{getattr(item, 'name', '')}:{getattr(item, 'timestamp', '')}", "raw_data": {"value": getattr(item, "value", None), "name": getattr(item, "name", None)}})

        if self.vm:
            vm_result = await self.vm.collect_metrics(service)
            if vm_result.get("success"):
                vm_metrics = vm_result.get("metrics", {})
                for name, value in vm_metrics.items():
                    if isinstance(value, (int, float)):
                        evidence.append({
                            "type": "metric",
                            "source": "vm_ssh",
                            "reference": f"vm:{service}:{name}:{since.isoformat()}",
                            "raw_data": {"name": name, "value": value, "target": service},
                        })
            else:
                evidence.append({
                    "type": "telemetry_error",
                    "source": "vm_ssh",
                    "reference": f"vm:{service}",
                    "raw_data": {"error": vm_result.get("error")},
                })

        return {"service": service, "since": since.isoformat(), "until": until.isoformat() if until else None, "evidence": evidence}
