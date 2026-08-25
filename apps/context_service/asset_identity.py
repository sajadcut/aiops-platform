from __future__ import annotations

from typing import Any, Dict, Iterable, List, Optional

from pydantic import BaseModel, Field


class AssetContext(BaseModel):
    asset_id: Optional[str] = None
    asset_type: str = "unknown"
    hostname: Optional[str] = None
    platform: str = "unknown"
    os_family: str = "unknown"
    os_version: Optional[str] = None
    environment: Optional[str] = None
    service: Optional[str] = None
    business_service: Optional[str] = None
    owner: Optional[str] = None
    cluster: Optional[str] = None
    namespace: Optional[str] = None
    workload_kind: Optional[str] = None
    workload: Optional[str] = None
    pod: Optional[str] = None
    node: Optional[str] = None
    datacenter: Optional[str] = None
    ip_addresses: List[str] = Field(default_factory=list)
    tags: Dict[str, str] = Field(default_factory=dict)
    source_refs: List[str] = Field(default_factory=list)
    source_confidence: Dict[str, float] = Field(default_factory=dict)
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)


class AssetIdentityResolver:
    """Deterministically derives one asset identity from live-source metadata.

    No LLM inference is used. Explicit source metadata wins over naming heuristics.
    Zabbix inventory/tags, Prometheus labels and Elastic ECS/Kubernetes fields are
    normalized into one contract consumed by Context/Triage.
    """

    SOURCE_WEIGHT = {"zabbix": 1.0, "prometheus": 0.9, "elasticsearch": 0.85, "kubernetes_api": 1.0, "vm_ssh": 1.0}

    @classmethod
    def resolve(cls, evidence: Iterable[Dict[str, Any]], service_hint: Optional[str] = None) -> Dict[str, Any]:
        candidates: List[tuple[float, str, Dict[str, Any]]] = []
        source_refs: List[str] = []
        source_confidence: Dict[str, float] = {}
        for item in evidence:
            if not isinstance(item, dict):
                continue
            source = str(item.get("source") or "unknown").lower()
            raw = item.get("raw_data") or {}
            if not isinstance(raw, dict):
                continue
            parsed = cls._extract(source, raw)
            if not parsed:
                continue
            weight = cls.SOURCE_WEIGHT.get(source, 0.6)
            candidates.append((weight, source, parsed))
            source_confidence[source] = max(source_confidence.get(source, 0.0), weight)
            ref = item.get("reference") or item.get("id")
            if ref and str(ref) not in source_refs:
                source_refs.append(str(ref))

        merged: Dict[str, Any] = {"service": service_hint}
        tags: Dict[str, str] = {}
        ips: List[str] = []
        # low confidence first, authoritative source last
        for weight, source, parsed in sorted(candidates, key=lambda row: row[0]):
            for key, value in parsed.items():
                if key == "tags" and isinstance(value, dict):
                    tags.update({str(k).lower(): str(v) for k, v in value.items() if v not in (None, "")})
                elif key == "ip_addresses" and isinstance(value, list):
                    for ip in value:
                        text = str(ip).strip()
                        if text and text not in ips:
                            ips.append(text)
                elif value not in (None, "", "unknown", []):
                    merged[key] = value

        cls._apply_tags(merged, tags)
        cls._derive_platform(merged)
        score = 0.0
        if merged.get("hostname") or merged.get("asset_id"):
            score += 0.25
        if merged.get("asset_type") not in (None, "unknown"):
            score += 0.25
        if merged.get("platform") not in (None, "unknown") or merged.get("os_family") not in (None, "unknown"):
            score += 0.25
        if merged.get("service") or merged.get("cluster") or merged.get("namespace"):
            score += 0.15
        if len(source_confidence) >= 2:
            score += 0.10

        return AssetContext(
            **merged,
            tags=tags,
            ip_addresses=ips,
            source_refs=source_refs,
            source_confidence=source_confidence,
            confidence=min(1.0, score),
        ).model_dump(mode="json")

    @classmethod
    def _extract(cls, source: str, raw: Dict[str, Any]) -> Dict[str, Any]:
        if source == "zabbix":
            return cls._from_zabbix(raw)
        if source == "prometheus":
            return cls._from_prometheus(raw)
        if source == "elasticsearch":
            return cls._from_elastic(raw)
        if source == "kubernetes_api":
            return cls._from_kubernetes(raw)
        if source == "vm_ssh":
            return {"asset_type": "vm", "platform": "vm", "os_family": "linux", "hostname": raw.get("target")}
        return {}

    @staticmethod
    def _from_zabbix(raw: Dict[str, Any]) -> Dict[str, Any]:
        host = raw.get("host") or {}
        if isinstance(host, list):
            host = host[0] if host else {}
        inventory = host.get("inventory") or raw.get("inventory") or {}
        tags = {}
        for tag in (raw.get("tags") or []) + (host.get("tags") or []):
            if isinstance(tag, dict) and tag.get("tag"):
                tags[str(tag["tag"]).lower()] = str(tag.get("value", ""))
        groups = [str(g.get("name", "")) for g in host.get("groups", []) if isinstance(g, dict)]
        templates = [str(t.get("name", "")) for t in host.get("parentTemplates", []) if isinstance(t, dict)]
        interfaces = host.get("interfaces") or []
        ips = [str(i.get("ip")) for i in interfaces if isinstance(i, dict) and i.get("ip")]
        os_text = str(inventory.get("os_full") or inventory.get("os") or tags.get("os_family") or "")
        return {
            "asset_id": str(host.get("hostid") or raw.get("hostid") or "") or None,
            "hostname": host.get("host") or host.get("name") or raw.get("host"),
            "os_family": AssetIdentityResolver._os_family(os_text),
            "os_version": inventory.get("os_full") or inventory.get("os"),
            "environment": tags.get("environment") or tags.get("env"),
            "service": tags.get("service") or tags.get("service_name"),
            "business_service": tags.get("business_service"),
            "owner": tags.get("owner"),
            "cluster": tags.get("cluster"),
            "namespace": tags.get("namespace"),
            "workload": tags.get("workload"),
            "pod": tags.get("pod"),
            "node": tags.get("node"),
            "datacenter": tags.get("datacenter") or inventory.get("site_address_a"),
            "asset_type": tags.get("asset_type") or AssetIdentityResolver._classify_text(" ".join(groups + templates)),
            "tags": tags,
            "ip_addresses": ips,
        }

    @staticmethod
    def _from_prometheus(raw: Dict[str, Any]) -> Dict[str, Any]:
        labels = raw.get("labels") or raw.get("metric") or {}
        if not isinstance(labels, dict):
            labels = {}
        instance = str(labels.get("instance") or "").split(":")[0] or None
        return {
            "hostname": labels.get("hostname") or labels.get("host") or labels.get("node") or instance,
            "asset_type": labels.get("asset_type") or AssetIdentityResolver._classify_labels(labels),
            "platform": labels.get("platform") or labels.get("orchestrator"),
            "os_family": AssetIdentityResolver._os_family(str(labels.get("os") or labels.get("os_family") or labels.get("job") or "")),
            "environment": labels.get("environment") or labels.get("env"),
            "service": labels.get("service") or labels.get("service_name") or labels.get("app"),
            "cluster": labels.get("cluster") or labels.get("kubernetes_cluster"),
            "namespace": labels.get("namespace"),
            "workload_kind": labels.get("workload_kind") or labels.get("kind"),
            "workload": labels.get("workload") or labels.get("deployment") or labels.get("statefulset") or labels.get("daemonset"),
            "pod": labels.get("pod"),
            "node": labels.get("node"),
            "tags": {str(k).lower(): str(v) for k, v in labels.items() if v not in (None, "")},
        }

    @staticmethod
    def _from_elastic(raw: Dict[str, Any]) -> Dict[str, Any]:
        host = raw.get("host") or {}
        os_info = host.get("os") or raw.get("os") or {}
        service = raw.get("service") or {}
        kubernetes = raw.get("kubernetes") or {}
        labels = raw.get("labels") or {}
        if isinstance(service, str):
            service = {"name": service}
        return {
            "hostname": host.get("name") or raw.get("hostname") or raw.get("host.name"),
            "asset_id": host.get("id"),
            "asset_type": labels.get("asset_type") or AssetIdentityResolver._classify_elastic(raw),
            "platform": labels.get("platform") or ("kubernetes" if kubernetes else None),
            "os_family": AssetIdentityResolver._os_family(str(os_info.get("family") or os_info.get("name") or os_info.get("platform") or "")),
            "os_version": os_info.get("version") or os_info.get("full"),
            "environment": service.get("environment") or labels.get("environment") or labels.get("env"),
            "service": service.get("name") or raw.get("service.name") or labels.get("service"),
            "cluster": (kubernetes.get("cluster") or {}).get("name") if isinstance(kubernetes.get("cluster"), dict) else kubernetes.get("cluster"),
            "namespace": kubernetes.get("namespace") or raw.get("kubernetes.namespace"),
            "pod": (kubernetes.get("pod") or {}).get("name") if isinstance(kubernetes.get("pod"), dict) else kubernetes.get("pod"),
            "node": (kubernetes.get("node") or {}).get("name") if isinstance(kubernetes.get("node"), dict) else kubernetes.get("node"),
            "workload": labels.get("workload") or labels.get("deployment") or labels.get("statefulset"),
            "owner": labels.get("owner"),
            "tags": {str(k).lower(): str(v) for k, v in labels.items() if v not in (None, "")},
            "ip_addresses": host.get("ip", []) if isinstance(host.get("ip"), list) else ([host.get("ip")] if host.get("ip") else []),
        }

    @staticmethod
    def _from_kubernetes(raw: Dict[str, Any]) -> Dict[str, Any]:
        metadata = raw.get("metadata") or {}
        return {
            "asset_type": "kubernetes_workload",
            "platform": "kubernetes",
            "cluster": raw.get("cluster"),
            "namespace": metadata.get("namespace") or raw.get("namespace"),
            "workload_kind": raw.get("kind"),
            "workload": metadata.get("name") or raw.get("workload"),
            "pod": raw.get("pod"),
            "node": raw.get("node"),
            "service": raw.get("service"),
        }

    @staticmethod
    def _apply_tags(merged: Dict[str, Any], tags: Dict[str, str]) -> None:
        mapping = {
            "asset_type": ("asset_type", "target_type"), "platform": ("platform",),
            "os_family": ("os_family", "os"), "environment": ("environment", "env"),
            "service": ("service", "service_name", "app"), "business_service": ("business_service",),
            "owner": ("owner",), "cluster": ("cluster",), "namespace": ("namespace",),
            "workload_kind": ("workload_kind", "kind"), "workload": ("workload",),
            "pod": ("pod",), "node": ("node",), "datacenter": ("datacenter", "site"),
        }
        for field, keys in mapping.items():
            for key in keys:
                if tags.get(key):
                    merged[field] = tags[key]
                    break

    @staticmethod
    def _derive_platform(data: Dict[str, Any]) -> None:
        asset_type = str(data.get("asset_type") or "unknown").lower()
        if "kubernetes" in asset_type or data.get("cluster") or data.get("pod") or data.get("namespace"):
            data["platform"] = "kubernetes"
            if asset_type == "unknown":
                data["asset_type"] = "kubernetes_workload" if data.get("pod") or data.get("workload") else "kubernetes_node"
        elif data.get("os_family") in {"linux", "windows"}:
            data["platform"] = "vm" if data.get("platform") in (None, "unknown") else data["platform"]
            if asset_type == "unknown":
                data["asset_type"] = "vm"

    @staticmethod
    def _os_family(text: str) -> str:
        value = text.lower()
        if any(x in value for x in ("windows", "win32", "windows_server")):
            return "windows"
        if any(x in value for x in ("linux", "ubuntu", "debian", "rhel", "centos", "rocky", "alma", "suse")):
            return "linux"
        return "unknown"

    @staticmethod
    def _classify_text(text: str) -> str:
        value = text.lower()
        if any(x in value for x in ("kubernetes", "k8s")):
            return "kubernetes_node"
        if any(x in value for x in ("windows", "linux", "vmware", "virtual machine", "vm ")):
            return "vm"
        if any(x in value for x in ("database", "postgres", "oracle", "sql server")):
            return "database"
        return "unknown"

    @staticmethod
    def _classify_labels(labels: Dict[str, Any]) -> str:
        if labels.get("pod") or labels.get("namespace") or labels.get("deployment") or labels.get("kubernetes_io_hostname"):
            return "kubernetes_workload" if labels.get("pod") or labels.get("deployment") else "kubernetes_node"
        job = str(labels.get("job") or "").lower()
        if "node_exporter" in job or labels.get("instance"):
            return "vm"
        return "unknown"

    @staticmethod
    def _classify_elastic(raw: Dict[str, Any]) -> str:
        if raw.get("kubernetes") or raw.get("kubernetes.namespace") or raw.get("kubernetes.pod.name"):
            return "kubernetes_workload"
        if raw.get("host") or raw.get("host.name"):
            return "vm"
        return "unknown"
