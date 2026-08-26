from __future__ import annotations

from collections import Counter
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional

from domain.contracts.config import settings
from domain.contracts.logging import logger
from domain.schemas import IncidentCreate
from integrations.elasticsearch.mcp_client import ElasticsearchMCPClient
from integrations.prometheus.mcp_client import PrometheusMCPClient
from integrations.vm.mcp_client import VMEdgeMCPClient
from integrations.zabbix.mcp_client import ZabbixMCPClient
from integrations.kubernetes.mcp_client import KubernetesMCPClient

from .evidence_collector import EvidenceCollector


class ContextBuilder:
    """Build operational context through governed MCP external-tool boundaries.

    The Control Plane never connects directly to Zabbix, Elasticsearch,
    Prometheus, Kubernetes or VM/Edge systems. Native connectors may exist for
    MCP server-side adapters/tests, but are not instantiated here.
    """

    def __init__(self, collector: Optional[EvidenceCollector] = None):
        if collector is not None:
            self.collector = collector
            return
        vm = VMEdgeMCPClient() if settings.VM_MCP_URL else None
        kubernetes = KubernetesMCPClient() if settings.KUBERNETES_MCP_URL else None
        self.collector = EvidenceCollector(
            zabbix=ZabbixMCPClient(),
            elasticsearch=ElasticsearchMCPClient(),
            prometheus=PrometheusMCPClient(),
            vm=vm,
            kubernetes=kubernetes,
        )

    async def build_context(self, incident_data: IncidentCreate) -> Dict[str, Any]:
        requested_service = str(incident_data.service or "unknown").strip() or "unknown"
        since = datetime.now(timezone.utc) - timedelta(seconds=settings.AGENT_INITIAL_EVIDENCE_WINDOW_SECONDS)
        logger.info("Building MCP-backed live context for service=%s", requested_service)

        live = await self.collector.collect(requested_service, since)
        asset = dict(live.get("asset_context") or {})
        resolved_service = str(asset.get("service") or live.get("service") or requested_service)
        evidence = list(live.get("evidence") or [])

        type_counts = Counter(str(item.get("type") or "unknown") for item in evidence if isinstance(item, dict))
        source_counts = Counter(str(item.get("source") or "unknown") for item in evidence if isinstance(item, dict))

        numeric_metrics: Dict[str, list[float]] = {}
        for item in evidence:
            if not isinstance(item, dict) or item.get("type") != "metric":
                continue
            raw = item.get("raw_data") or {}
            name = str(raw.get("name") or "")
            value = raw.get("value")
            if name and isinstance(value, (int, float)):
                numeric_metrics.setdefault(name, []).append(float(value))

        def avg(name: str):
            values = numeric_metrics.get(name, [])
            return sum(values) / len(values) if values else None

        return {
            "incident": incident_data.model_dump(mode="json"),
            "service": resolved_service,
            "time_window": {"since": live.get("since"), "until": live.get("until")},
            "asset_context": asset,
            "live_evidence": live,
            "evidence": evidence,
            "summary": {
                "evidence_count": len(evidence),
                "evidence_type_counts": dict(type_counts),
                "evidence_source_counts": dict(source_counts),
                "log_count": type_counts.get("log", 0),
                "metric_count": type_counts.get("metric", 0),
                "alert_count": type_counts.get("alert", 0),
                "source_observation_count": type_counts.get("source_observation", 0),
                "avg_cpu": avg("cpu_usage"),
                "avg_memory": avg("memory_usage"),
                "error_rate": avg("error_rate"),
            },
        }
