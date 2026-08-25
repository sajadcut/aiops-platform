from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, Iterable, List, Optional, Set

from apps.context_service.asset_identity import AssetIdentityResolver
from domain.contracts.config import settings
from integrations.kubernetes.client import KubernetesEvidenceClient


class EvidenceCollector:
    """Read-only live Evidence boundary used by orchestration.

    Collection is intentionally two-stage for alert-driven incidents:
    1) resolve target identity from authoritative alert/source metadata;
    2) query Elastic/Prometheus/Kubernetes/VM with the resolved service/asset.
    Agents never execute free-form connector commands.
    """

    _KNOWN_TYPES = {"alert", "log", "metric", "event", "telemetry"}
    _UNKNOWN_SERVICE_VALUES = {"", "unknown", "unknown-service", "none", "null"}

    def __init__(self, zabbix=None, elasticsearch=None, prometheus=None, vm=None, kubernetes=None):
        self.zabbix = zabbix
        self.elasticsearch = elasticsearch
        self.prometheus = prometheus
        self.vm = vm
        self.kubernetes = kubernetes
        if self.kubernetes is None and settings.KUBERNETES_API_URL:
            self.kubernetes = KubernetesEvidenceClient()

    @classmethod
    def _known_service(cls, value: Optional[str]) -> Optional[str]:
        text = str(value or "").strip()
        return None if text.lower() in cls._UNKNOWN_SERVICE_VALUES else text

    async def collect(self, service: str, since: datetime, until: datetime | None = None) -> Dict[str, Any]:
        return await self._collect(service, since, until, requested_types=None)

    async def collect_requested(self, service: str, since: datetime, requests: Iterable[Dict[str, Any] | str], until: datetime | None = None) -> Dict[str, Any]:
        types: Set[str] = set()
        for request in requests:
            value = request.get("evidence_type") if isinstance(request, dict) else request
            canonical = str(value or "").strip().lower()
            if canonical in self._KNOWN_TYPES:
                types.add(canonical)
            if len(types) >= settings.AGENT_MAX_DYNAMIC_EVIDENCE_TYPES:
                break
        if not types:
            return {"service": service, "since": since.isoformat(), "until": until.isoformat() if until else None, "requested_types": [], "evidence": [], "asset_context": AssetIdentityResolver.resolve([], self._known_service(service))}
        result = await self._collect(service, since, until, requested_types=types)
        result["requested_types"] = sorted(types)
        return result

    @staticmethod
    def _alert_evidence(items: List[Any]) -> List[Dict[str, Any]]:
        return [{
            "type": "alert",
            "source": getattr(item, "source", "zabbix"),
            "reference": getattr(item, "source_id", None),
            "timestamp": getattr(item, "timestamp", None),
            "raw_data": getattr(item, "raw_data", {}),
        } for item in items]

    async def _collect(self, service: str, since: datetime, until: Optional[datetime], requested_types: Optional[Set[str]]) -> Dict[str, Any]:
        wants_all = requested_types is None
        wants = requested_types or set()
        evidence: List[Dict[str, Any]] = []
        requested_service = self._known_service(service)

        # Stage 1: Alert/asset identity. An unknown service must not be used as a host filter.
        alerts: List[Any] = []
        if self.zabbix and (wants_all or "alert" in wants):
            alerts = await self.zabbix.get_alerts(since=since, service=requested_service)
            evidence.extend(self._alert_evidence(alerts))

        partial_asset = AssetIdentityResolver.resolve(evidence, requested_service)
        effective_service = self._known_service(partial_asset.get("service")) or self._known_service(partial_asset.get("hostname")) or requested_service
        query_service = effective_service or service

        # Stage 2: Correlate the resolved asset across the other live evidence sources.
        logs: List[Any] = []
        metrics: List[Any] = []
        if self.elasticsearch and (wants_all or "log" in wants) and effective_service:
            logs = await self.elasticsearch.get_logs(effective_service, since, until)
        if self.prometheus and (wants_all or "metric" in wants) and effective_service:
            metrics = await self.prometheus.get_metrics(effective_service, ["up", "cpu_usage", "memory_usage"], since, until)

        for item in logs:
            evidence.append({
                "type": "log", "source": getattr(item, "source", "elasticsearch"),
                "reference": f"log:{getattr(item, 'timestamp', '')}", "timestamp": getattr(item, "timestamp", None),
                "raw_data": getattr(item, "raw_data", {}),
            })
        for item in metrics:
            evidence.append({
                "type": "metric", "source": getattr(item, "source", "prometheus"),
                "reference": f"metric:{getattr(item, 'name', '')}:{getattr(item, 'timestamp', '')}", "timestamp": getattr(item, "timestamp", None),
                "raw_data": {"value": getattr(item, "value", None), "name": getattr(item, "name", None), "labels": getattr(item, "labels", {}) or {}, "service": getattr(item, "service", None)},
            })

        asset = AssetIdentityResolver.resolve(evidence, effective_service)
        effective_service = self._known_service(asset.get("service")) or self._known_service(asset.get("hostname")) or effective_service

        if self.kubernetes and getattr(self.kubernetes, "enabled", False) and effective_service and (wants_all or "event" in wants):
            try:
                k8s_evidence = await self.kubernetes.collect_evidence(effective_service)
                evidence.extend(k8s_evidence)
                asset = AssetIdentityResolver.resolve(evidence, effective_service)
            except Exception as exc:
                evidence.append({"type": "telemetry_error", "source": "kubernetes_api", "reference": f"k8s:{effective_service}", "timestamp": since.isoformat(), "raw_data": {"error": str(exc), "service": effective_service}})

        # SSH is Linux-specific; only call it when identity says Linux/VM, or when an explicit service hint was supplied.
        should_query_vm = bool(self.vm and effective_service and (wants_all or "telemetry" in wants or "metric" in wants))
        if should_query_vm and str(asset.get("os_family") or "unknown").lower() != "windows" and str(asset.get("platform") or "unknown").lower() != "kubernetes":
            vm_result = await self.vm.collect_metrics(effective_service)
            if vm_result.get("success"):
                for name, value in (vm_result.get("metrics") or {}).items():
                    if isinstance(value, (int, float)):
                        evidence.append({"type": "metric", "source": "vm_ssh", "reference": f"vm:{effective_service}:{name}:{since.isoformat()}", "timestamp": since.isoformat(), "raw_data": {"name": name, "value": value, "target": effective_service}})
            else:
                evidence.append({"type": "telemetry_error", "source": "vm_ssh", "reference": f"vm:{effective_service}", "timestamp": since.isoformat(), "raw_data": {"error": vm_result.get("error"), "target": effective_service}})

        final_asset = AssetIdentityResolver.resolve(evidence, effective_service)
        return {
            "service": effective_service or query_service,
            "requested_service": service,
            "since": since.isoformat(),
            "until": until.isoformat() if until else None,
            "evidence": evidence,
            "asset_context": final_asset,
        }
