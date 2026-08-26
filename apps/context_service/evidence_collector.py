from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Set

from apps.context_service.asset_identity import AssetIdentityResolver
from domain.contracts.config import settings


class EvidenceCollector:
    """Read-only cross-source Evidence boundary used by orchestration.

    Collection is intentionally two-stage:
    1) establish/strengthen asset identity from source metadata;
    2) actively query the other configured sources for corroborating evidence.

    Every attempted source query emits a ``source_observation`` record. This
    lets reasoning distinguish "Zabbix was checked and had no matching alert"
    from "Zabbix was unavailable/not queried". No free-form Agent command is
    ever forwarded to a connector.

    External connectors are injected by ContextBuilder and, for the production
    Control Plane, are MCP-backed providers. This class intentionally has no
    native Kubernetes/SSH/observability fallback path.
    """

    _KNOWN_TYPES = {"alert", "log", "metric", "event", "telemetry"}
    _UNKNOWN_SERVICE_VALUES = {"", "unknown", "unknown-service", "none", "null"}

    def __init__(self, zabbix=None, elasticsearch=None, prometheus=None, vm=None, kubernetes=None):
        self.zabbix = zabbix
        self.elasticsearch = elasticsearch
        self.prometheus = prometheus
        self.vm = vm
        self.kubernetes = kubernetes

    @classmethod
    def _known_service(cls, value: Optional[str]) -> Optional[str]:
        text = str(value or "").strip()
        return None if text.lower() in cls._UNKNOWN_SERVICE_VALUES else text

    @staticmethod
    def _observation(source: str, reference: str, *, status: str, result_count: int = 0, service: Optional[str] = None, detail: Optional[str] = None) -> Dict[str, Any]:
        return {
            "type": "source_observation",
            "source": source,
            "reference": reference,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "confidence": 1.0,
            "raw_data": {
                "status": status,
                "result_count": int(result_count),
                "service": service,
                "detail": detail,
            },
        }

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
            return {
                "service": service,
                "since": since.isoformat(),
                "until": until.isoformat() if until else None,
                "requested_types": [],
                "evidence": [],
                "asset_context": AssetIdentityResolver.resolve([], self._known_service(service)),
            }
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

    async def _healthy(self, connector: Any) -> bool:
        if connector is None:
            return False
        check = getattr(connector, "health_check", None)
        if not callable(check):
            return True
        try:
            return bool(await check())
        except Exception:
            return False

    async def _collect(self, service: str, since: datetime, until: Optional[datetime], requested_types: Optional[Set[str]]) -> Dict[str, Any]:
        wants_all = requested_types is None
        wants = requested_types or set()
        evidence: List[Dict[str, Any]] = []
        requested_service = self._known_service(service)

        alerts: List[Any] = []
        if self.zabbix and (wants_all or "alert" in wants):
            healthy = await self._healthy(self.zabbix)
            if healthy:
                try:
                    alerts = await self.zabbix.get_alerts(since=since, service=requested_service)
                    evidence.extend(self._alert_evidence(alerts))
                    evidence.append(self._observation(
                        "zabbix", f"zabbix-observation:{since.isoformat()}",
                        status="queried", result_count=len(alerts), service=requested_service,
                        detail="matching_active_alerts",
                    ))
                except Exception as exc:
                    evidence.append(self._observation("zabbix", f"zabbix-error:{since.isoformat()}", status="error", service=requested_service, detail=str(exc)))
            else:
                evidence.append(self._observation("zabbix", f"zabbix-unavailable:{since.isoformat()}", status="unavailable", service=requested_service))

        partial_asset = AssetIdentityResolver.resolve(evidence, requested_service)
        effective_service = self._known_service(partial_asset.get("service")) or self._known_service(partial_asset.get("hostname")) or requested_service
        query_service = effective_service or service

        logs: List[Any] = []
        metrics: List[Any] = []
        if self.elasticsearch and (wants_all or "log" in wants):
            if not effective_service:
                evidence.append(self._observation("elasticsearch", f"elastic-skipped:{since.isoformat()}", status="skipped", detail="asset_service_unresolved"))
            elif await self._healthy(self.elasticsearch):
                try:
                    logs = await self.elasticsearch.get_logs(effective_service, since, until)
                    evidence.append(self._observation(
                        "elasticsearch", f"elastic-observation:{effective_service}:{since.isoformat()}",
                        status="queried", result_count=len(logs), service=effective_service, detail="matching_logs",
                    ))
                except Exception as exc:
                    evidence.append(self._observation("elasticsearch", f"elastic-error:{since.isoformat()}", status="error", service=effective_service, detail=str(exc)))
            else:
                evidence.append(self._observation("elasticsearch", f"elastic-unavailable:{since.isoformat()}", status="unavailable", service=effective_service))

        if self.prometheus and (wants_all or "metric" in wants):
            if not effective_service:
                evidence.append(self._observation("prometheus", f"prom-skipped:{since.isoformat()}", status="skipped", detail="asset_service_unresolved"))
            elif await self._healthy(self.prometheus):
                try:
                    metrics = await self.prometheus.get_metrics(effective_service, ["up", "cpu_usage", "memory_usage", "error_rate"], since, until)
                    evidence.append(self._observation(
                        "prometheus", f"prom-observation:{effective_service}:{since.isoformat()}",
                        status="queried", result_count=len(metrics), service=effective_service, detail="matching_metric_samples",
                    ))
                except Exception as exc:
                    evidence.append(self._observation("prometheus", f"prom-error:{since.isoformat()}", status="error", service=effective_service, detail=str(exc)))
            else:
                evidence.append(self._observation("prometheus", f"prom-unavailable:{since.isoformat()}", status="unavailable", service=effective_service))

        for item in logs:
            evidence.append({
                "type": "log",
                "source": getattr(item, "source", "elasticsearch"),
                "reference": f"log:{getattr(item, 'timestamp', '')}",
                "timestamp": getattr(item, "timestamp", None),
                "raw_data": getattr(item, "raw_data", {}),
            })
        for item in metrics:
            evidence.append({
                "type": "metric",
                "source": getattr(item, "source", "prometheus"),
                "reference": f"metric:{getattr(item, 'name', '')}:{getattr(item, 'timestamp', '')}",
                "timestamp": getattr(item, "timestamp", None),
                "raw_data": {
                    "value": getattr(item, "value", None),
                    "name": getattr(item, "name", None),
                    "labels": getattr(item, "labels", {}) or {},
                    "service": getattr(item, "service", None),
                },
            })

        asset = AssetIdentityResolver.resolve(evidence, effective_service)
        effective_service = self._known_service(asset.get("service")) or self._known_service(asset.get("hostname")) or effective_service

        if self.kubernetes and getattr(self.kubernetes, "enabled", False) and (wants_all or "event" in wants):
            if not effective_service:
                evidence.append(self._observation("kubernetes_api", f"k8s-skipped:{since.isoformat()}", status="skipped", detail="asset_service_unresolved"))
            else:
                try:
                    k8s_evidence = await self.kubernetes.collect_evidence(effective_service)
                    evidence.extend(k8s_evidence)
                    evidence.append(self._observation(
                        "kubernetes_api", f"k8s-observation:{effective_service}:{since.isoformat()}",
                        status="queried", result_count=len(k8s_evidence), service=effective_service,
                    ))
                    asset = AssetIdentityResolver.resolve(evidence, effective_service)
                except Exception as exc:
                    evidence.append(self._observation("kubernetes_api", f"k8s-error:{since.isoformat()}", status="error", service=effective_service, detail=str(exc)))

        should_query_vm = bool(self.vm and effective_service and (wants_all or "telemetry" in wants or "metric" in wants))
        if should_query_vm and str(asset.get("os_family") or "unknown").lower() != "windows" and str(asset.get("platform") or "unknown").lower() != "kubernetes":
            try:
                vm_result = await self.vm.collect_metrics(effective_service)
                if vm_result.get("success"):
                    vm_metrics = vm_result.get("metrics") or {}
                    for name, value in vm_metrics.items():
                        if isinstance(value, (int, float)):
                            evidence.append({
                                "type": "metric", "source": "vm_mcp",
                                "reference": f"vm:{effective_service}:{name}:{since.isoformat()}",
                                "timestamp": datetime.now(timezone.utc).isoformat(),
                                "raw_data": {"name": name, "value": value, "target": effective_service},
                            })
                    evidence.append(self._observation("vm_mcp", f"vm-observation:{effective_service}:{since.isoformat()}", status="queried", result_count=len(vm_metrics), service=effective_service))
                else:
                    evidence.append(self._observation("vm_mcp", f"vm-error:{effective_service}:{since.isoformat()}", status="error", service=effective_service, detail=str(vm_result.get("error"))))
            except Exception as exc:
                evidence.append(self._observation("vm_mcp", f"vm-error:{effective_service}:{since.isoformat()}", status="error", service=effective_service, detail=str(exc)))

        final_asset = AssetIdentityResolver.resolve(evidence, effective_service)
        return {
            "service": effective_service or query_service,
            "requested_service": service,
            "since": since.isoformat(),
            "until": until.isoformat() if until else None,
            "evidence": evidence,
            "asset_context": final_asset,
        }
