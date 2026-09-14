from __future__ import annotations

from datetime import datetime, timezone

import pytest

from apps.context_service import ContextBuilder
from apps.context_service.knowledge_topology import KnowledgeTopologyResolver
from apps.rag_service import KnowledgeRAGService
from apps.signal_gateway import SignalGateway, signal_from_zabbix
from domain.schemas import IncidentCreate


TOPOLOGY_DOC = {
    "id": "cognia:1:10:20:30",
    "source_id": "cognia:1:10:20:30",
    "content": """Service: web-api
URL: https://web.wepod.ir
Platform: Kubernetes
Cluster: prod-k8s
Namespace: wepod-prod
Workload Kind: Deployment
Workload: web-api
Repository: https://git.example/wepod/web-api.git
Jenkins Job: production/wepod/web-api
Owner: digital-platform
""",
    "relevance": 12.5,
}


class FakeRAG:
    def __init__(self, results):
        self.results = list(results)
        self.calls = []

    async def search(self, query: str, limit: int = 5, **kwargs):
        self.calls.append({"query": query, "limit": limit, "kwargs": kwargs})
        return list(self.results)


class FakeCollector:
    def __init__(self, asset):
        self.asset = dict(asset)
        self.services = []

    async def collect(self, service, since, until=None):
        self.services.append(service)
        return {
            "service": self.asset.get("service") or service,
            "since": since.isoformat(),
            "until": until.isoformat() if until else None,
            "evidence": [{
                "type": "alert",
                "source": "zabbix",
                "reference": "zbx-1",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "raw_data": {"signal_summary": 'Download speed for "web.wepod.ir" has slowed down.'},
            }],
            "asset_context": dict(self.asset),
        }


def test_topology_resolver_normalizes_full_url_and_extracts_deployment_hints():
    topology = KnowledgeTopologyResolver.resolve(
        [TOPOLOGY_DOC],
        expected_fqdns=["web.wepod.ir"],
    )
    assert topology["fields"]["fqdn"] == "web.wepod.ir"
    assert topology["fields"]["service"] == "web-api"
    assert topology["fields"]["platform"] == "kubernetes"
    assert topology["fields"]["namespace"] == "wepod-prod"
    assert topology["fields"]["jenkins_job"] == "production/wepod/web-api"
    assert topology["skipped_mismatched_fqdns"] == []


def test_topology_resolver_rejects_a_document_for_another_fqdn():
    topology = KnowledgeTopologyResolver.resolve(
        [{**TOPOLOGY_DOC, "content": TOPOLOGY_DOC["content"].replace("web.wepod.ir", "admin.wepod.ir")}],
        expected_fqdns=["web.wepod.ir"],
    )
    assert topology["fields"] == {}
    assert topology["skipped_mismatched_fqdns"] == ["admin.wepod.ir"]


def test_live_topology_wins_and_conflict_is_explicit():
    topology = KnowledgeTopologyResolver.resolve([TOPOLOGY_DOC], expected_fqdns=["web.wepod.ir"])
    reconciled = KnowledgeTopologyResolver.reconcile(
        {
            "service": "web-api",
            "platform": "kubernetes",
            "cluster": "prod-k8s",
            "namespace": "wepod-prod-v2",
            "workload": "web-api",
            "confidence": 0.9,
        },
        topology,
    )
    assert reconciled["effective_asset"]["namespace"] == "wepod-prod-v2"
    assert reconciled["field_provenance"]["namespace"] == "live"
    assert any(
        item.get("field") == "namespace" and item.get("kind") == "live_vs_knowledge"
        for item in reconciled["conflicts"]
    )
    assert reconciled["requires_live_verification"] is True


def test_unknown_live_placeholders_do_not_override_cognia_identity():
    topology = KnowledgeTopologyResolver.resolve([TOPOLOGY_DOC], expected_fqdns=["web.wepod.ir"])
    reconciled = KnowledgeTopologyResolver.reconcile(
        {"service": "web-api", "asset_type": "unknown", "platform": "unknown", "confidence": 0.25},
        topology,
    )
    assert reconciled["effective_asset"]["platform"] == "kubernetes"
    assert reconciled["field_provenance"]["platform"] == "knowledge"
    assert "platform" in reconciled["knowledge_identity_fields"]
    assert reconciled["requires_live_verification"] is True


@pytest.mark.asyncio
async def test_context_builder_always_queries_cognia_and_uses_topology_to_seed_live_lookup():
    rag = FakeRAG([TOPOLOGY_DOC])
    collector = FakeCollector({
        "service": "web-api",
        "asset_type": "unknown",
        "platform": "unknown",
        "confidence": 0.25,
    })
    context = await ContextBuilder(collector=collector, rag_service=rag).build_context(
        IncidentCreate(
            source="zabbix",
            severity="warning",
            summary='Download speed for "web.wepod.ir" has slowed down.',
        )
    )

    assert len(rag.calls) == 1
    assert "web.wepod.ir" in rag.calls[0]["query"]
    assert collector.services == ["web-api"]
    assert context["asset_context"]["service"] == "web-api"
    assert context["asset_context"]["platform"] == "kubernetes"
    assert context["asset_context"]["namespace"] == "wepod-prod"
    assert context["asset_context"]["field_provenance"]["service"] == "live"
    assert context["asset_context"]["field_provenance"]["platform"] == "knowledge"
    assert context["asset_context"]["requires_live_verification"] is True
    assert context["topology_context"]["deployment_hints"]["jenkins_job"] == "production/wepod/web-api"
    assert context["knowledge_status"]["status"] == "available"
    assert context["summary"]["knowledge_count"] == 1


@pytest.mark.asyncio
async def test_context_builder_queries_cognia_even_when_live_asset_is_complete():
    rag = FakeRAG([TOPOLOGY_DOC])
    collector = FakeCollector({
        "service": "web-api",
        "asset_type": "kubernetes_workload",
        "platform": "kubernetes",
        "cluster": "prod-k8s",
        "namespace": "wepod-prod",
        "workload_kind": "deployment",
        "workload": "web-api",
        "confidence": 1.0,
    })
    context = await ContextBuilder(collector=collector, rag_service=rag).build_context(
        IncidentCreate(
            source="zabbix",
            severity="warning",
            service="web-api",
            summary="HTTP status 500 for https://web.wepod.ir",
        )
    )

    assert len(rag.calls) == 1
    # Cognia may enrich auxiliary metadata such as owner, but all execution-
    # sensitive identity fields remain live-provenanced so no extra write block
    # is introduced by that auxiliary enrichment alone.
    assert context["asset_context"]["knowledge_assisted"] is True
    assert context["asset_context"]["requires_live_verification"] is False
    assert context["asset_context"]["field_provenance"]["platform"] == "live"
    assert context["asset_context"]["field_provenance"]["namespace"] == "live"
    assert context["asset_context"]["field_provenance"]["owner"] == "knowledge"
    assert context["topology_context"]["knowledge_identity_fields"] == []
    assert context["topology_context"]["deployment_hints"]["repository"].endswith("/web-api.git")


@pytest.mark.asyncio
async def test_zabbix_web_scenario_signal_uses_cognia_when_host_is_only_monitoring_container(monkeypatch):
    async def fake_search(self, query: str, limit: int = 5, **kwargs):
        assert "web.wepod.ir" in query
        return [TOPOLOGY_DOC]

    monkeypatch.setattr(KnowledgeRAGService, "search", fake_search)
    signal = signal_from_zabbix({
        "eventid": "z-web-500",
        "host": "wepod.ir",
        "name": 'Problem: Download speed for "web.wepod.ir" has slowed down.',
        "severity": "warning",
    })
    assert signal.service is None

    discovery = await SignalGateway._knowledge_assisted_asset(signal, signal.to_evidence())
    asset = discovery["asset_context"]
    assert asset["hostname"] == "wepod.ir"
    assert asset["service"] == "web-api"
    assert asset["platform"] == "kubernetes"
    assert asset["namespace"] == "wepod-prod"
    assert asset["requires_live_verification"] is True
    assert discovery["knowledge_status"]["status"] == "available"
