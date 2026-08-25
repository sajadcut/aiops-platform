from typing import Any, Dict, List
from datetime import datetime


class EvidenceCollector:
    """Combines live operational evidence; live evidence remains authoritative.

    Specialized Agents do not call connectors directly. Read-only Evidence is
    collected here and then supplied to Agent context.
    """

    def __init__(self, zabbix=None, elasticsearch=None, prometheus=None, vm=None, kubernetes=None):
        self.zabbix = zabbix
        self.elasticsearch = elasticsearch
        self.prometheus = prometheus
        self.vm = vm
        self.kubernetes = kubernetes

    async def collect(self, service: str, since: datetime, until: datetime | None = None) -> Dict[str, Any]:
        alerts: List[Any] = []
        logs: List[Any] = []
        metrics: List[Any] = []
        evidence: List[Dict[str, Any]] = []

        if self.zabbix:
            alerts = await self.zabbix.get_alerts(since=since, service=service)
        if self.elasticsearch:
            logs = await self.elasticsearch.get_logs(service, since, until)
        if self.prometheus:
            metrics = await self.prometheus.get_metrics(service, ["up", "rate(http_requests_total[5m])"], since, until)

        for item in alerts:
            evidence.append({
                "type": "alert", "source": "zabbix",
                "reference": getattr(item, "source_id", None),
                "timestamp": getattr(item, "timestamp", None),
                "raw_data": getattr(item, "raw_data", {}),
            })
        for item in logs:
            evidence.append({
                "type": "log", "source": "elasticsearch",
                "reference": f"log:{getattr(item, 'timestamp', '')}",
                "timestamp": getattr(item, "timestamp", None),
                "raw_data": getattr(item, "raw_data", {}),
            })
        for item in metrics:
            evidence.append({
                "type": "metric", "source": "prometheus",
                "reference": f"metric:{getattr(item, 'name', '')}:{getattr(item, 'timestamp', '')}",
                "timestamp": getattr(item, "timestamp", None),
                "raw_data": {"value": getattr(item, "value", None), "name": getattr(item, "name", None)},
            })

        if self.kubernetes and getattr(self.kubernetes, "enabled", False):
            try:
                evidence.extend(await self.kubernetes.collect_evidence(service))
            except Exception as exc:
                evidence.append({
                    "type": "telemetry_error",
                    "source": "kubernetes_api",
                    "reference": f"k8s:{service}",
                    "raw_data": {"error": str(exc)},
                })

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
                            "timestamp": since.isoformat(),
                            "raw_data": {"name": name, "value": value, "target": service},
                        })
            else:
                evidence.append({
                    "type": "telemetry_error",
                    "source": "vm_ssh",
                    "reference": f"vm:{service}",
                    "timestamp": since.isoformat(),
                    "raw_data": {"error": vm_result.get("error")},
                })

        return {
            "service": service,
            "since": since.isoformat(),
            "until": until.isoformat() if until else None,
            "evidence": evidence,
        }
