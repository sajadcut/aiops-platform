from __future__ import annotations

from collections import Counter
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional

from apps.rag_service import KnowledgeRAGService
from domain.contracts.config import settings
from domain.contracts.logging import logger
from domain.schemas import IncidentCreate
from integrations.cognia import CogniaAPIError, CogniaConfigurationError, CogniaContractError
from integrations.elasticsearch.mcp_client import ElasticsearchMCPClient
from integrations.prometheus.mcp_client import PrometheusMCPClient
from integrations.vm.mcp_client import VMEdgeMCPClient, vm_transport_configured
from integrations.zabbix.mcp_client import ZabbixMCPClient
from integrations.kubernetes.mcp_client import KubernetesMCPClient

from .evidence_collector import EvidenceCollector
from .knowledge_topology import KnowledgeTopologyResolver
from .knowledge_relevance import filter_service_knowledge
from .service_identity import ServiceIdentityResolver


class ContextBuilder:
    """Build knowledge-assisted operational context through governed boundaries.

    Cognia is always queried first for service/topology knowledge so sparse
    alerts such as a bare URL can be mapped to a likely service/platform before
    live-source collection begins. The mapping remains auxiliary: Zabbix,
    Elasticsearch, Prometheus, Kubernetes and VM/Edge MCP evidence is
    authoritative, and any Cognia-only topology field is marked for live
    verification before a write may rely on it.

    The Control Plane never connects directly to Zabbix, Elasticsearch,
    Prometheus, Kubernetes or VM/Edge systems. Native connectors may exist for
    MCP server-side adapters/tests, but are not instantiated here.
    """

    def __init__(
        self,
        collector: Optional[EvidenceCollector] = None,
        rag_service: Optional[KnowledgeRAGService] = None,
    ):
        self.rag_service = rag_service or KnowledgeRAGService()
        if collector is not None:
            self.collector = collector
            return
        vm = VMEdgeMCPClient() if vm_transport_configured() else None
        kubernetes = KubernetesMCPClient() if settings.KUBERNETES_MCP_URL else None
        self.collector = EvidenceCollector(
            zabbix=ZabbixMCPClient(),
            elasticsearch=ElasticsearchMCPClient(),
            prometheus=PrometheusMCPClient(),
            vm=vm,
            kubernetes=kubernetes,
        )

    @staticmethod
    def _known(value: Any) -> Optional[str]:
        text = str(value or "").strip()
        if text.lower() in {"", "unknown", "unknown-service", "none", "null"}:
            return None
        return text

    @staticmethod
    def _knowledge_failure_status(exc: Exception) -> Dict[str, Any]:
        if isinstance(exc, CogniaConfigurationError):
            return {"provider": "cognia", "status": "misconfigured", "code": str(exc)}
        if isinstance(exc, CogniaContractError):
            return {"provider": "cognia", "status": "invalid_contract", "code": str(exc)}
        if isinstance(exc, CogniaAPIError):
            if exc.status_code == 401:
                status = "authentication_failed"
            elif exc.status_code == 403:
                status = "forbidden"
            elif exc.status_code == 404:
                status = "not_accessible"
            elif exc.status_code in {429, 502, 503, 504}:
                status = "unavailable"
            else:
                status = "error"
            result: Dict[str, Any] = {
                "provider": "cognia",
                "status": status,
                "code": exc.code,
                "http_status": exc.status_code,
            }
            if exc.trace_id:
                result["trace_id"] = exc.trace_id
            return result
        return {"provider": "cognia", "status": "error", "code": type(exc).__name__}

    async def build_context(self, incident_data: IncidentCreate) -> Dict[str, Any]:
        incident = incident_data.model_dump(mode="json")
        explicit_service = self._known(incident_data.service)
        discovery_query = KnowledgeTopologyResolver.build_discovery_query(incident)
        expected_fqdns = ServiceIdentityResolver.expected_fqdns(
            summary=incident_data.summary,
            context=incident_data.context,
        )

        knowledge_results = []
        relevance_audit: Dict[str, Any] = {}
        knowledge_status: Dict[str, Any] = {
            "provider": "cognia",
            "status": "not_queried",
            "count": 0,
            "phase": "asset_discovery",
        }
        try:
            raw_results = await self.rag_service.search(
                discovery_query,
                limit=min(20, max(5, settings.AGENT_MAX_AUXILIARY_CONTEXT_ITEMS * 3))
                    if explicit_service else settings.AGENT_MAX_AUXILIARY_CONTEXT_ITEMS,
            )
            knowledge_results, relevance_audit = filter_service_knowledge(
                raw_results, expected_service=explicit_service,
                expected_fqdns=expected_fqdns,
                purpose="context_asset_discovery",
            )
            knowledge_results = knowledge_results[:settings.AGENT_MAX_AUXILIARY_CONTEXT_ITEMS]
            knowledge_status = {
                "provider": "cognia",
                "status": ("filtered_empty" if relevance_audit["rejected_count"] and not knowledge_results
                           else "available" if knowledge_results else "empty"),
                "count": len(knowledge_results),
                "phase": "asset_discovery",
                "relevance": relevance_audit,
            }
            if relevance_audit["rejected_count"]:
                logger.info("cognia_service_relevance_filtered",
                            service=explicit_service, phase="asset_discovery",
                            accepted=len(knowledge_results),
                            rejected=relevance_audit["rejected_count"],
                            rejected_refs=[x["source_id"] for x in relevance_audit["rejected"]])
        except Exception as exc:
            knowledge_status = {
                **self._knowledge_failure_status(exc),
                "count": 0,
                "phase": "asset_discovery",
            }
            logger.warning(
                "asset_discovery_knowledge_query_failed",
                status=knowledge_status.get("status"),
                code=knowledge_status.get("code"),
            )

        knowledge_topology = KnowledgeTopologyResolver.resolve(
            knowledge_results,
            expected_fqdns=expected_fqdns,
            expected_service=explicit_service,
        )
        initial_resolution = ServiceIdentityResolver.resolve(
            source_service=explicit_service,
            live_asset={},
            knowledge_topology=knowledge_topology,
            expected_fqdns=expected_fqdns,
        )
        knowledge_service = self._known((knowledge_topology.get("fields") or {}).get("service"))
        requested_service = initial_resolution["service"]
        since = datetime.now(timezone.utc) - timedelta(seconds=settings.AGENT_INITIAL_EVIDENCE_WINDOW_SECONDS)
        logger.info(
            "building_knowledge_assisted_context",
            requested_service=requested_service,
            explicit_service=explicit_service,
            knowledge_service=knowledge_service,
            knowledge_count=len(knowledge_results),
        )

        live = await self.collector.collect(requested_service, since)
        live_asset = dict(live.get("asset_context") or {})
        resolution = ServiceIdentityResolver.resolve(
            source_service=explicit_service,
            live_asset=live_asset,
            knowledge_topology=knowledge_topology,
            expected_fqdns=expected_fqdns,
        )
        topology_context = resolution["topology_context"]
        asset = resolution["asset_context"]
        resolved_service = resolution["service"]
        evidence = list(live.get("evidence") or [])

        live = {
            **live,
            "asset_context": asset,
            "service_identity": resolution["service_identity"],
            "live_asset_context": live_asset,
            "knowledge_topology": knowledge_topology,
            "topology_context": topology_context,
        }

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
            "incident": incident,
            "service": resolved_service,
            "service_identity": resolution["service_identity"],
            "time_window": {"since": live.get("since"), "until": live.get("until")},
            "asset_context": asset,
            "live_asset_context": live_asset,
            "topology_context": topology_context,
            "knowledge_results": knowledge_results,
            "knowledge_status": knowledge_status,
            "knowledge_discovery_query": discovery_query,
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
                "knowledge_count": len(knowledge_results),
                "knowledge_assisted_asset": bool(asset.get("knowledge_assisted")),
                "topology_conflict_count": len(topology_context.get("conflicts") or []),
                "asset_requires_live_verification": bool(topology_context.get("requires_live_verification")),
                "avg_cpu": avg("cpu_usage"),
                "avg_memory": avg("memory_usage"),
                "error_rate": avg("error_rate"),
            },
        }
