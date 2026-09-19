from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Set

from apps.context_service.asset_identity import AssetIdentityResolver
from domain.contracts.config import settings
from integrations.vm.target_context import current_vm_port, current_vm_target


class EvidenceCollector:
    """Read-only cross-source Evidence boundary used by orchestration.

    Agent prose is never forwarded as a command. Evidence requests are mapped
    to a fixed set of connector methods, while provider failures can degrade to
    equivalent VM-local evidence (for example journal logs when Elastic is
    unavailable).
    """

    _KNOWN_TYPES = {"alert", "log", "metric", "event", "telemetry"}
    _UNKNOWN_SERVICE_VALUES = {"", "unknown", "unknown-service", "none", "null"}
    _NON_MATERIAL_OBSERVATION_STATUSES = {"unavailable", "error", "skipped"}
    _VM_ACTIONS = {
        "collect_vm_metrics", "host_info", "disk_status", "network_status",
        "service_status", "service_logs", "system_logs", "process_snapshot",
        "process_status", "tcp_check", "port_listener_status", "dns_check",
        "route_check", "firewall_status", "config_validate",
    }

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
    def _vm_target_from_asset(asset: Dict[str, Any]) -> Optional[str]:
        for value in asset.get("ip_addresses") or []:
            target = str(value or "").strip()
            if target:
                return target
        hostname = str(asset.get("hostname") or "").strip()
        return hostname or None

    @staticmethod
    def _observation(source: str, reference: str, *, status: str, result_count: int = 0, service: Optional[str] = None, detail: Optional[str] = None) -> Dict[str, Any]:
        return {
            "type": "source_observation", "source": source, "reference": reference,
            "timestamp": datetime.now(timezone.utc).isoformat(), "confidence": 1.0,
            "raw_data": {"status": status, "result_count": int(result_count), "service": service, "detail": detail},
        }

    @classmethod
    def _is_non_material_observation(cls, item: Dict[str, Any]) -> bool:
        if str(item.get("type") or "").strip().lower() != "source_observation":
            return False
        raw = item.get("raw_data") or {}
        status = str(raw.get("status") or "").strip().lower() if isinstance(raw, dict) else ""
        return status in cls._NON_MATERIAL_OBSERVATION_STATUSES

    @staticmethod
    def _normalize_requests(requests: Iterable[Dict[str, Any] | str]) -> List[Dict[str, str]]:
        normalized: List[Dict[str, str]] = []
        for request in requests:
            if isinstance(request, dict):
                evidence_type = str(request.get("evidence_type") or "").strip().lower()
                reason = str(request.get("reason") or "").strip()
                preferred_source = str(request.get("preferred_source") or "").strip().lower()
            else:
                evidence_type = str(request or "").strip().lower()
                reason = ""
                preferred_source = ""
            if evidence_type not in EvidenceCollector._KNOWN_TYPES:
                continue
            row = {"evidence_type": evidence_type, "reason": reason, "preferred_source": preferred_source}
            if row not in normalized:
                normalized.append(row)
            if len(normalized) >= settings.AGENT_MAX_DYNAMIC_EVIDENCE_TYPES:
                break
        return normalized

    @classmethod
    def _vm_actions_for_requests(
        cls, requests: Optional[List[Dict[str, str]]], *, service: Optional[str], port: Optional[int], elastic_logs_available: bool,
    ) -> List[str]:
        actions: List[str] = []

        def add(action: str) -> None:
            if action in cls._VM_ACTIONS and action not in actions:
                actions.append(action)

        if requests is None:
            add("collect_vm_metrics")
            add("host_info")
            add("disk_status")
            if service:
                add("service_status")
                add("process_status")
                add("config_validate")
            if port:
                add("port_listener_status")
                add("tcp_check")
            return actions

        for request in requests:
            evidence_type = request["evidence_type"]
            reason = request["reason"].lower()
            preferred = request["preferred_source"]
            text = f"{evidence_type} {reason} {preferred}"

            if evidence_type == "metric" or any(token in text for token in ("cpu", "memory", "swap", "load", "io wait", "vm metric")):
                add("collect_vm_metrics")
            if any(token in text for token in ("host info", "hostname", "kernel", "uptime", "operating system", " os ")):
                add("host_info")
            if any(token in text for token in ("disk", "inode", "mount", "filesystem", "file system")):
                add("disk_status")
            if any(token in text for token in ("interface", "routing table", "default gateway", "network status")):
                add("network_status")
            if service and any(token in text for token in ("service status", "systemd", "active state", "substate", "restart count")):
                add("service_status")
            if service and any(token in text for token in ("process", "pid", "zombie", "duplicate process")):
                add("process_status")
            if any(token in text for token in ("process snapshot", "top process")):
                add("process_snapshot")
            if port and any(token in text for token in ("port", "listener", "listening", "bind", "socket")):
                add("port_listener_status")
                add("tcp_check")
            if service and any(token in text for token in ("config", "configuration", "syntax validation")):
                add("config_validate")
            if any(token in text for token in ("firewall", "iptables", "nftables", "firewalld", " acl")):
                add("firewall_status")
            if evidence_type == "log" and service and (preferred in {"vm", "journal", "systemd"} or not elastic_logs_available):
                add("service_logs")
            if evidence_type == "telemetry" and not any(action in actions for action in ("service_status", "process_status", "port_listener_status", "config_validate", "host_info", "disk_status", "network_status", "firewall_status")):
                add("collect_vm_metrics")
        return actions

    async def collect(self, service: str, since: datetime, until: datetime | None = None) -> Dict[str, Any]:
        return await self._collect(service, since, until, requested_types=None, requests=None)

    async def collect_requested(self, service: str, since: datetime, requests: Iterable[Dict[str, Any] | str], until: datetime | None = None) -> Dict[str, Any]:
        request_rows = self._normalize_requests(requests)
        types: Set[str] = {item["evidence_type"] for item in request_rows}
        if not types:
            return {
                "service": service, "since": since.isoformat(), "until": until.isoformat() if until else None,
                "requested_types": [], "evidence": [], "source_observations": [],
                "asset_context": AssetIdentityResolver.resolve([], self._known_service(service)),
            }
        result = await self._collect(service, since, until, requested_types=types, requests=request_rows)
        result["requested_types"] = sorted(types)
        result["requested_evidence"] = request_rows
        all_evidence = list(result.get("evidence") or [])
        non_material = [item for item in all_evidence if isinstance(item, dict) and self._is_non_material_observation(item)]
        result["source_observations"] = non_material
        result["evidence"] = [item for item in all_evidence if item not in non_material]
        return result

    @staticmethod
    def _alert_evidence(items: List[Any]) -> List[Dict[str, Any]]:
        return [{
            "type": "alert", "source": getattr(item, "source", "zabbix"),
            "reference": getattr(item, "source_id", None), "timestamp": getattr(item, "timestamp", None),
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

    @staticmethod
    def _vm_evidence(action: str, target: str, service: Optional[str], port: Optional[int], result: Dict[str, Any], since: datetime) -> List[Dict[str, Any]]:
        now = datetime.now(timezone.utc).isoformat()
        if action == "collect_vm_metrics":
            rows: List[Dict[str, Any]] = []
            for name, value in (result.get("metrics") or {}).items():
                if isinstance(value, (int, float)):
                    rows.append({
                        "type": "metric", "source": "vm_mcp", "reference": f"vm:{target}:{name}:{since.isoformat()}",
                        "timestamp": now, "raw_data": {"name": name, "value": value, "target": target, "service": service, "diagnostic": action},
                    })
            return rows
        if action in {"service_logs", "system_logs"}:
            entries = [str(item) for item in (result.get("logs") or []) if str(item).strip()][-40:]
            return [{
                "type": "log", "source": "vm_mcp", "reference": f"vm:{target}:{action}:{since.isoformat()}",
                "timestamp": now, "raw_data": {"diagnostic": action, "target": target, "service": service, "entries": entries, "count": len(entries)},
            }]
        payload = dict(result)
        payload.update({"diagnostic": action, "target": target, "service": service})
        if port is not None:
            payload["target_port"] = port
        return [{
            "type": "telemetry", "source": "vm_mcp", "reference": f"vm:{target}:{action}:{since.isoformat()}",
            "timestamp": now, "raw_data": payload,
        }]

    async def _collect(self, service: str, since: datetime, until: Optional[datetime], requested_types: Optional[Set[str]], requests: Optional[List[Dict[str, str]]]) -> Dict[str, Any]:
        wants_all = requested_types is None
        wants = requested_types or set()
        evidence: List[Dict[str, Any]] = []
        requested_service = self._known_service(service)

        if self.zabbix and (wants_all or "alert" in wants):
            if await self._healthy(self.zabbix):
                try:
                    alerts = await self.zabbix.get_alerts(since=since, service=requested_service)
                    evidence.extend(self._alert_evidence(alerts))
                    evidence.append(self._observation("zabbix", f"zabbix-observation:{since.isoformat()}", status="queried", result_count=len(alerts), service=requested_service, detail="matching_active_alerts"))
                except Exception as exc:
                    evidence.append(self._observation("zabbix", f"zabbix-error:{since.isoformat()}", status="error", service=requested_service, detail=str(exc)))
            else:
                evidence.append(self._observation("zabbix", f"zabbix-unavailable:{since.isoformat()}", status="unavailable", service=requested_service))

        if self.prometheus and (wants_all or "alert" in wants):
            get_alerts = getattr(self.prometheus, "get_alerts", None)
            if callable(get_alerts):
                if await self._healthy(self.prometheus):
                    try:
                        prom_alerts = await get_alerts(since=since, service=requested_service)
                        evidence.extend(self._alert_evidence(prom_alerts))
                        evidence.append(self._observation(
                            "prometheus",
                            f"prom-alert-observation:{since.isoformat()}",
                            status="queried",
                            result_count=len(prom_alerts),
                            service=requested_service,
                            detail="matching_active_alerts_via_mcp",
                        ))
                    except Exception as exc:
                        evidence.append(self._observation(
                            "prometheus",
                            f"prom-alert-error:{since.isoformat()}",
                            status="error",
                            service=requested_service,
                            detail=str(exc),
                        ))
                else:
                    evidence.append(self._observation(
                        "prometheus",
                        f"prom-alert-unavailable:{since.isoformat()}",
                        status="unavailable",
                        service=requested_service,
                    ))

        partial_asset = AssetIdentityResolver.resolve(evidence, requested_service)
        effective_service = self._known_service(partial_asset.get("service")) or self._known_service(partial_asset.get("hostname")) or requested_service
        query_service = effective_service or service

        logs: List[Any] = []
        metrics: List[Any] = []
        elastic_logs_available = False
        if self.elasticsearch and (wants_all or "log" in wants):
            if not effective_service:
                evidence.append(self._observation("elasticsearch", f"elastic-skipped:{since.isoformat()}", status="skipped", detail="asset_service_unresolved"))
            elif await self._healthy(self.elasticsearch):
                try:
                    logs = await self.elasticsearch.get_logs(effective_service, since, until)
                    elastic_logs_available = True
                    evidence.append(self._observation("elasticsearch", f"elastic-observation:{effective_service}:{since.isoformat()}", status="queried", result_count=len(logs), service=effective_service, detail="matching_logs"))
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
                    evidence.append(self._observation("prometheus", f"prom-observation:{effective_service}:{since.isoformat()}", status="queried", result_count=len(metrics), service=effective_service, detail="matching_metric_samples"))
                except Exception as exc:
                    evidence.append(self._observation("prometheus", f"prom-error:{since.isoformat()}", status="error", service=effective_service, detail=str(exc)))
            else:
                evidence.append(self._observation("prometheus", f"prom-unavailable:{since.isoformat()}", status="unavailable", service=effective_service))

        for item in logs:
            evidence.append({"type": "log", "source": getattr(item, "source", "elasticsearch"), "reference": f"log:{getattr(item, 'timestamp', '')}", "timestamp": getattr(item, "timestamp", None), "raw_data": getattr(item, "raw_data", {})})
        for item in metrics:
            evidence.append({
                "type": "metric", "source": getattr(item, "source", "prometheus"),
                "reference": f"metric:{getattr(item, 'name', '')}:{getattr(item, 'timestamp', '')}", "timestamp": getattr(item, "timestamp", None),
                "raw_data": {"value": getattr(item, "value", None), "name": getattr(item, "name", None), "labels": getattr(item, "labels", {}) or {}, "service": getattr(item, "service", None)},
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
                    evidence.append(self._observation("kubernetes_api", f"k8s-observation:{effective_service}:{since.isoformat()}", status="queried", result_count=len(k8s_evidence), service=effective_service))
                    asset = AssetIdentityResolver.resolve(evidence, effective_service)
                except Exception as exc:
                    evidence.append(self._observation("kubernetes_api", f"k8s-error:{since.isoformat()}", status="error", service=effective_service, detail=str(exc)))

        vm_target = current_vm_target() or self._vm_target_from_asset(asset)
        vm_port = current_vm_port()
        linux_candidate = str(asset.get("os_family") or "unknown").lower() != "windows" and str(asset.get("platform") or "unknown").lower() != "kubernetes"
        if self.vm and vm_target and linux_candidate:
            actions = self._vm_actions_for_requests(requests, service=effective_service, port=vm_port, elastic_logs_available=elastic_logs_available)
            for action in actions:
                method = getattr(self.vm, action, None)
                if not callable(method):
                    evidence.append(self._observation("vm_mcp", f"vm-skipped:{vm_target}:{action}:{since.isoformat()}", status="skipped", service=effective_service, detail="diagnostic_not_supported"))
                    continue
                try:
                    if action in {"service_status", "service_logs", "config_validate"}:
                        result = await method(vm_target, effective_service)
                    elif action == "process_status":
                        result = await method(vm_target, effective_service)
                    elif action == "port_listener_status":
                        result = await method(vm_target, vm_port)
                    elif action == "tcp_check":
                        result = await method(vm_target, vm_target, vm_port)
                    else:
                        result = await method(vm_target)
                    if isinstance(result, dict) and result.get("success"):
                        rows = self._vm_evidence(action, vm_target, effective_service, vm_port, result, since)
                        evidence.extend(rows)
                        evidence.append(self._observation("vm_mcp", f"vm-observation:{vm_target}:{action}:{since.isoformat()}", status="queried", result_count=len(rows), service=effective_service, detail=f"target={vm_target};diagnostic={action}"))
                    else:
                        detail = str((result or {}).get("error") if isinstance(result, dict) else "invalid_result")
                        evidence.append(self._observation("vm_mcp", f"vm-error:{vm_target}:{action}:{since.isoformat()}", status="error", service=effective_service, detail=detail))
                except Exception as exc:
                    evidence.append(self._observation("vm_mcp", f"vm-error:{vm_target}:{action}:{since.isoformat()}", status="error", service=effective_service, detail=str(exc)))

        final_asset = AssetIdentityResolver.resolve(evidence, effective_service)
        return {
            "service": effective_service or query_service, "requested_service": service,
            "vm_target": vm_target, "vm_port": vm_port, "since": since.isoformat(),
            "until": until.isoformat() if until else None, "evidence": evidence, "asset_context": final_asset,
        }
