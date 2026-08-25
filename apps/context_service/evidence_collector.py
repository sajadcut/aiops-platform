from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, Iterable, List, Optional, Set

from domain.contracts.config import settings
from integrations.kubernetes.client import KubernetesEvidenceClient


class EvidenceCollector:
    """Read-only live Evidence boundary used by orchestration.

    Specialized Agents never call operational connectors directly. The initial
    context pass may collect all configured sources; later Agent evidence rounds
    pass canonical evidence types here, which are mapped to allowlisted read
    connectors. Free-form LLM commands are never executed.
    """

    _KNOWN_TYPES = {"alert", "log", "metric", "event", "telemetry"}

    def __init__(self, zabbix=None, elasticsearch=None, prometheus=None, vm=None, kubernetes=None):
        self.zabbix = zabbix
        self.elasticsearch = elasticsearch
        self.prometheus = prometheus
        self.vm = vm
        self.kubernetes = kubernetes
        if self.kubernetes is None and settings.KUBERNETES_API_URL:
            self.kubernetes = KubernetesEvidenceClient()

    async def collect(self, service: str, since: datetime, until: datetime | None = None) -> Dict[str, Any]:
        """Collect the full configured read-only Evidence set."""
        return await self._collect(service, since, until, requested_types=None)

    async def collect_requested(
        self,
        service: str,
        since: datetime,
        requests: Iterable[Dict[str, Any] | str],
        until: datetime | None = None,
    ) -> Dict[str, Any]:
        """Collect only canonical evidence types requested by Agent coordination.

        Unknown/free-form types are ignored rather than forwarded to connectors.
        This keeps the dynamic evidence loop bounded and non-executable.
        """
        types: Set[str] = set()
        for request in requests:
            value = request.get("evidence_type") if isinstance(request, dict) else request
            canonical = str(value or "").strip().lower()
            if canonical in self._KNOWN_TYPES:
                types.add(canonical)
            if len(types) >= settings.AGENT_MAX_DYNAMIC_EVIDENCE_TYPES:
                break
        if not types:
            return {
                "service": service,
                "since": since.isoformat(),
                "until": until.isoformat() if until else None,
                "requested_types": [],
                "evidence": [],
            }
        result = await self._collect(service, since, until, requested_types=types)
        result["requested_types"] = sorted(types)
        return result

    async def _collect(
        self,
        service: str,
        since: datetime,
        until: Optional[datetime],
        requested_types: Optional[Set[str]],
    ) -> Dict[str, Any]:
        wants_all = requested_types is None
        wants = requested_types or set()
        alerts: List[Any] = []
        logs: List[Any] = []
        metrics: List[Any] = []
        evidence: List[Dict[str, Any]] = []

        if self.zabbix and (wants_all or "alert" in wants):
            alerts = await self.zabbix.get_alerts(since=since, service=service)
        if self.elasticsearch and (wants_all or "log" in wants):
            logs = await self.elasticsearch.get_logs(service, since, until)
        if self.prometheus and (wants_all or "metric" in wants):
            # Keep collection generic and read-only; specialist interpretation is performed by Agents.
            metrics = await self.prometheus.get_metrics(service, ["up"], since, until)

        for item in alerts:
            evidence.append({
                "type": "alert",
                "source": "zabbix",
                "reference": getattr(item, "source_id", None),
                "timestamp": getattr(item, "timestamp", None),
                "raw_data": getattr(item, "raw_data", {}),
            })
        for item in logs:
            evidence.append({
                "type": "log",
                "source": "elasticsearch",
                "reference": f"log:{getattr(item, 'timestamp', '')}",
                "timestamp": getattr(item, "timestamp", None),
                "raw_data": getattr(item, "raw_data", {}),
            })
        for item in metrics:
            evidence.append({
                "type": "metric",
                "source": "prometheus",
                "reference": f"metric:{getattr(item, 'name', '')}:{getattr(item, 'timestamp', '')}",
                "timestamp": getattr(item, "timestamp", None),
                "raw_data": {"value": getattr(item, "value", None), "name": getattr(item, "name", None)},
            })

        if self.kubernetes and getattr(self.kubernetes, "enabled", False) and (wants_all or "event" in wants):
            try:
                evidence.extend(await self.kubernetes.collect_evidence(service))
            except Exception as exc:
                evidence.append({
                    "type": "telemetry_error",
                    "source": "kubernetes_api",
                    "reference": f"k8s:{service}",
                    "timestamp": since.isoformat(),
                    "raw_data": {"error": str(exc)},
                })

        if self.vm and (wants_all or "telemetry" in wants or "metric" in wants):
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
