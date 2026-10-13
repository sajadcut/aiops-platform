"""GFPAPI Cognia retrieval regression: never promote irrelevant Nginx docs."""
from __future__ import annotations

from datetime import datetime, timezone
from types import SimpleNamespace
from uuid import UUID

import pytest

from apps.context_service import ContextBuilder
from apps.context_service.knowledge_relevance import filter_service_knowledge
from apps.context_service.knowledge_topology import KnowledgeTopologyResolver
from apps.orchestrator.dynamic_investigation import DynamicInvestigationPlanner
from domain.schemas import IncidentCreate


NGINX_DOC = {
    "source_id": "cognia:1:115:126:2425",
    "relevance": 0.4187094569206238,
    "content": "Service: nginx\nPlatform: VM\nOwner: operations\nDescription: server setup",
}
GFPAPI_DOC = {
    "source_id": "cognia:1:116:127:2500",
    "relevance": 0.34,
    "content": "Service: gfpapi\nPlatform: VM\nRuntime: dotnet\nOwner: app-team",
}
GENERIC_DOC = {
    "source_id": "cognia:1:200:210:2200",
    "relevance": 0.95,
    "content": "Diagnose ASP.NET Core systemd Type=notify readiness and startup timeout",
}


class RAG:
    def __init__(self, rows):
        self.rows = rows
        self.calls = []
    async def search(self, query, limit=5, **kwargs):
        self.calls.append({"query": query, "limit": limit, **kwargs})
        return list(self.rows)


class Collector:
    def __init__(self):
        self.services = []
    async def collect(self, service, since, until=None):
        self.services.append(service)
        return {
            "service": service, "since": since.isoformat(),
            "until": datetime.now(timezone.utc).isoformat(),
            "evidence": [], "asset_context": {
                "service": service, "platform": "vm",
            },
        }


def test_service_bound_filter_disallows_high_score_foreign_owner_and_keeps_generic():
    documents, audit = filter_service_knowledge(
        [NGINX_DOC, GFPAPI_DOC, GENERIC_DOC],
        expected_service="GFPAPI.service",
        purpose="incident",
    )
    assert [x["source_id"] for x in documents] == [
        "cognia:1:116:127:2500", "cognia:1:200:210:2200"
    ]
    assert audit["status"] == "filtered"
    assert audit["rejected_count"] == 1
    assert audit["rejected"][0]["reason"] == "document_service_conflicts_with_incident"
    assert audit["rejected"][0]["declared_service"] == "nginx"
    assert "nginx" not in "".join(doc["content"] for doc in documents).lower()


def test_non_scoped_incidents_still_allow_discovery_from_service_hint():
    result, audit = filter_service_knowledge(
        [NGINX_DOC], expected_service=None
    )
    assert result == [NGINX_DOC]
    assert audit["rejected_count"] == 0


def test_topology_defense_in_depth_blocks_wrong_service_and_generic_owner_promotion():
    topology = KnowledgeTopologyResolver.resolve(
        [NGINX_DOC, GENERIC_DOC, GFPAPI_DOC],
        expected_service="gfpapi",
    )
    assert topology["fields"]["service"] == "gfpapi"
    assert topology["fields"]["owner"] == "app-team"
    assert topology["skipped_service_mismatch"] == ["cognia:1:115:126:2425"]
    assert topology["skipped_unscoped_topology"] == ["cognia:1:200:210:2200"]
    assert "nginx" not in str(topology["fields"]).lower()


@pytest.mark.asyncio
async def test_context_builder_mixed_kb_returns_gfpapi_only_not_nginx():
    rag = RAG([NGINX_DOC, GFPAPI_DOC, GENERIC_DOC])
    collector = Collector()
    result = await ContextBuilder(
        collector=collector, rag_service=rag
    ).build_context(IncidentCreate(
        source="zabbix", severity="high", service="gfpapi",
        summary="GFPAPI Systemd Service Down",
        context={"platform": "vm", "target_ip": "10.248.16.82"},
    ))
    assert collector.services == ["gfpapi"]
    assert result["service"] == "gfpapi"
    assert result["asset_context"]["service"] == "gfpapi"
    assert result["topology_context"]["conflicts"] == []
    assert "nginx" not in [r.get("service") for r in result["knowledge_results"]]
    assert [r["source_id"] for r in result["knowledge_results"]] == [
        GFPAPI_DOC["source_id"], GENERIC_DOC["source_id"]]
    audit = result["knowledge_status"]["relevance"]
    assert audit["returned_count"] == 3 and audit["rejected_count"] == 1
    assert rag.calls[0]["limit"] > 5


@pytest.mark.asyncio
async def test_signal_gateway_filters_nginx_before_correlation(monkeypatch):
    from apps.signal_gateway import SignalGateway, OperationalSignal
    from apps.rag_service import KnowledgeRAGService
    async def search(*args, **kwargs):
        return [NGINX_DOC, GFPAPI_DOC]
    monkeypatch.setattr(KnowledgeRAGService, "search", search)
    signal = OperationalSignal(
        source="zabbix", source_id="event-123",
        signal_type="systemd service down", severity="high",
        summary="GFPAPI Systemd Service Down", service="gfpapi",
        raw_data={"platform": "vm", "target_ip": "10.248.16.82"},
    )
    result = await SignalGateway._knowledge_assisted_asset(
        signal, signal.to_evidence()
    )
    assert [x["source_id"] for x in result["knowledge_results"]] == [GFPAPI_DOC["source_id"]]
    assert result["service_identity"]["service"] == "gfpapi"
    assert result["knowledge_status"]["relevance"]["rejected_count"] == 1
    assert result["topology_context"]["conflicts"] == []


@pytest.mark.asyncio
async def test_focused_rag_rejects_wrong_service_and_scrubs_old_knowledge():
    state = {
        "incident_id": "incident-1", "service_name": "gfpapi",
        "knowledge_results": [NGINX_DOC],
        "context": {
            "evidence": [{
                "source": "vm_mcp", "reference": "runtime-1",
                "raw_data": {
                    "diagnostic": "service_runtime_discovery",
                    "runtime": "dotnet", "service": "gfpapi",
                    "entrypoint": "/data/gfp/gfpapi/GFP.Endpoints.API.dll",
                },
            }],
        },
    }
    rag = RAG([NGINX_DOC, GENERIC_DOC])
    result = await DynamicInvestigationPlanner.enrich_knowledge(state, rag=rag)
    assert result["status"] == "retrieved"
    assert result["source_refs"] == [GENERIC_DOC["source_id"]]
    assert [x["source_id"] for x in state["knowledge_results"]] == [GENERIC_DOC["source_id"]]
    assert state["context"]["knowledge_relevance_followup"]["rejected_count"] == 1
    assert state["context"]["knowledge_relevance_followup"]["rejected_prior_count"] == 1


@pytest.mark.asyncio
async def test_incident_copilot_cognia_read_is_service_scoped(monkeypatch):
    from apps.api.incident_chat import _read_cognia
    from apps.rag_service import KnowledgeRAGService
    async def search(*args, **kwargs):
        return [NGINX_DOC, GFPAPI_DOC]
    monkeypatch.setattr(KnowledgeRAGService, "search", search)
    result = await _read_cognia(
        "بررسی دانش مربوط به سرویس", "gfpapi", {},
        UUID("c0a812d6-7d12-4fab-b454-fe5ac4d7c37a"),
    )
    assert result["success"] is True
    assert result["knowledge_relevance"]["rejected"] == 1
    assert [x["source_ref"] for x in result["documents"]] == [GFPAPI_DOC["source_id"]]
    assert "nginx" not in str(result["documents"]).lower()


@pytest.mark.asyncio
async def test_all_foreign_service_hits_are_explicitly_reported_as_filtered_empty():
    rag = RAG([NGINX_DOC])
    result = await ContextBuilder(
        collector=Collector(), rag_service=rag
    ).build_context(IncidentCreate(
        source="zabbix", severity="high", service="gfpapi",
        summary="GFPAPI Systemd Service Down",
    ))
    assert result["knowledge_results"] == []
    assert result["knowledge_status"]["status"] == "filtered_empty"
    assert result["knowledge_status"]["relevance"]["rejected"][0]["source_id"] == NGINX_DOC["source_id"]
    assert result["service"] == "gfpapi"
