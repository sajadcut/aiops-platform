"""Prevent wrong nginx service identity for unrelated host/OS alerts."""
from __future__ import annotations

import pytest

from apps.context_service.knowledge_topology import KnowledgeTopologyResolver
from apps.signal_gateway import SignalGateway, signal_from_zabbix


NGINX_DOCUMENT = {
    "source_id": "cognia:1:incidental-nginx",
    "content": "Service: nginx\nPlatform: VM\nOwner: frontend",
    "relevance": 0.39,
}


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "payload",
    [
        {
            "eventid": "136247345", "event_status": "PROBLEM",
            "name": "test", "trigger": "test",
            "host_name": "apeirdtnksa0101", "host_ip": "10.248.41.69",
            "tags": [{"tag": "Application", "value": "Filesystem /"}],
            "operational_data": "Space used: (14.81 %)",
        },
        {
            "eventid": "136247653", "event_status": "PROBLEM",
            "name": "High memory utilization (>90% for 5m)",
            "host_name": "APORSDTNKSA0101", "host_ip": "10.248.41.67",
            "tags": [{"tag": "Application", "value": "Memory"}],
            "operational_data": "91.22 %",
        },
    ],
)
async def test_unrelated_memory_and_filesystem_alerts_do_not_become_nginx(monkeypatch, payload):
    from apps.rag_service import KnowledgeRAGService

    async def search(self, *args, **kwargs):
        return [NGINX_DOCUMENT]

    monkeypatch.setattr(KnowledgeRAGService, "search", search)
    signal = signal_from_zabbix(payload)
    assert signal.service is None

    discovery = await SignalGateway._knowledge_assisted_asset(signal, signal.to_evidence())
    assert discovery["knowledge_status"]["status"] == "available"
    assert discovery["knowledge_results"] == [NGINX_DOCUMENT]
    assert discovery["topology_context"]["unverified_knowledge_service_hint"] == "nginx"
    assert discovery["topology_context"]["service_identity_basis"] == "unverified_knowledge_hint_blocked"
    assert discovery["asset_context"]["service"] is None
    assert discovery["asset_context"]["requires_live_verification"] is True


@pytest.mark.asyncio
async def test_trusted_zabbix_tag_wins_over_unrelated_rag_identity(monkeypatch):
    from apps.rag_service import KnowledgeRAGService

    async def search(self, *args, **kwargs):
        return [NGINX_DOCUMENT]

    monkeypatch.setattr(KnowledgeRAGService, "search", search)
    signal = signal_from_zabbix({
        "eventid": "1362", "name": "payment service down",
        "tags": [{"tag": "service", "value": "payment-api"}],
    })
    discovery = await SignalGateway._knowledge_assisted_asset(signal, signal.to_evidence())
    assert discovery["asset_context"]["service"] == "payment-api"
    assert discovery["topology_context"]["field_provenance"]["service"] == "live"


@pytest.mark.asyncio
async def test_gateway_stores_unknown_service_instead_of_host_or_nginx(monkeypatch):
    from apps.rag_service import KnowledgeRAGService
    from apps.incident_service.repository import IncidentRepository
    from apps.orchestrator.learning_runtime import LearningDurableWorkflowRuntime

    async def search(self, *args, **kwargs):
        return [NGINX_DOCUMENT]

    monkeypatch.setattr(KnowledgeRAGService, "search", search)
    monkeypatch.setattr(IncidentRepository, "find_incident_by_evidence_reference", 
                        lambda self, **kwargs: _return_none())
    monkeypatch.setattr(IncidentRepository, "acquire_correlation_lock",
                        lambda self, key: _return_none())
    observed = {}

    async def fake_start(self, state):
        observed.update(state)
        return {"incident_id": state["incident_id"], "context": state["context"]}

    monkeypatch.setattr(LearningDurableWorkflowRuntime, "start", fake_start)
    signal = signal_from_zabbix({
        "eventid": "136249812", "name": "test2", "host_name": "apeirdtnksa0101",
        "tags": [{"tag": "Application", "value": "Memory"}],
    })
    result = await SignalGateway.ingest(object(), signal)
    assert result["correlation_key"] == "unknown:zabbix:136249812"
    assert observed["service_name"] == "unknown"
    assert observed["context"]["incident"]["service"] == "unknown"
    assert observed["context"]["incident"]["source_host"] == "apeirdtnksa0101"
    assert observed["context"]["trigger_signal"]["service"] is None
    assert observed["context"]["asset_context"]["service"] is None
    assert observed["context"]["topology_context"]["unverified_knowledge_service_hint"] == "nginx"


async def _return_none():
    return None


def test_exact_fqdn_match_allows_knowledge_service_as_a_hint_not_live_proof():
    topology = KnowledgeTopologyResolver.resolve([{
        "source_id": "cognia:1:verified-url",
        "content": "Service: web-api\nURL: https://web.wepod.ir\nPlatform: Kubernetes",
    }], expected_fqdns=["web.wepod.ir"])
    reconciled = KnowledgeTopologyResolver.constrain_trigger_service(
        KnowledgeTopologyResolver.reconcile({"service": None}, topology),
        expected_fqdns=["web.wepod.ir"],
    )
    assert reconciled["effective_asset"]["service"] == "web-api"
    assert reconciled["service_identity_basis"] == "source_fqdn_matches_knowledge"
    assert reconciled["requires_live_verification"] is True


def test_doc_without_explicit_fqdn_cannot_claim_service_from_generic_alarm():
    topology = KnowledgeTopologyResolver.resolve([NGINX_DOCUMENT])
    reconciled = KnowledgeTopologyResolver.constrain_trigger_service(
        KnowledgeTopologyResolver.reconcile({"service": None, "hostname": "APORSDTNKSA0101"}, topology),
        expected_fqdns=[],
    )
    assert reconciled["effective_asset"]["service"] is None
    assert reconciled["effective_asset"]["hostname"] == "APORSDTNKSA0101"
    assert reconciled["unverified_knowledge_service_hint"] == "nginx"
