import pytest

import apps.rag_service as rag_module
from apps.rag_service import KnowledgeRAGService
from domain.contracts.config import settings
from integrations.cognia import CogniaAPIError, CogniaContractError


class FakeCogniaClient:
    search_payload = None
    raised = None
    captured = None

    def __init__(self, *args, **kwargs):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return None

    async def search(self, query, **kwargs):
        type(self).captured = {"query": query, **kwargs}
        if type(self).raised:
            raise type(self).raised
        return type(self).search_payload

    async def generate_context(self, task, **kwargs):
        return {"isSufficient": False, "task": task, **kwargs}


@pytest.fixture(autouse=True)
def reset_fake():
    FakeCogniaClient.search_payload = None
    FakeCogniaClient.raised = None
    FakeCogniaClient.captured = None


@pytest.mark.asyncio
async def test_cognia_search_maps_chunk_traceability_without_inventing_title(monkeypatch):
    monkeypatch.setattr(settings, "COGNIA_KNOWLEDGE_BASE_IDS", [10, 20])
    monkeypatch.setattr(rag_module, "CogniaClient", FakeCogniaClient)
    FakeCogniaClient.search_payload = {
        "items": [
            {
                "rank": 1,
                "relevanceScore": 0.92,
                "knowledgeBaseId": 10,
                "knowledgeId": 9001,
                "revisionId": 12001,
                "revisionNumber": 3,
                "chunkId": 501,
                "chunkIndex": 7,
                "chunkText": "connection pool operational guidance",
                "startOffset": 1200,
                "endOffset": 1580,
                "approximateTokenCount": 110,
                "knowledgeType": "text",
                "scope": {"type": "general"},
            }
        ]
    }

    items = await KnowledgeRAGService().search(
        "connection pool",
        limit=5,
        min_similarity=0.5,
        scope_context={"clientApplicationId": 42},
    )

    assert FakeCogniaClient.captured == {
        "query": "connection pool",
        "knowledge_base_ids": [10, 20],
        "limit": 5,
        "scope_context": {"clientApplicationId": 42},
    }
    assert items == [
        {
            "id": "cognia:10:9001:12001:501",
            "source_id": "cognia:10:9001:12001:501",
            "provider": "cognia",
            "source": "cognia",
            "knowledge_base_id": 10,
            "knowledge_id": 9001,
            "revision_id": 12001,
            "revision_number": 3,
            "version": "3",
            "chunk_id": 501,
            "chunk_index": 7,
            "content": "connection pool operational guidance",
            "start_offset": 1200,
            "end_offset": 1580,
            "approximate_token_count": 110,
            "knowledge_type": "text",
            "scope": {"type": "general"},
            "rank": 1,
            "relevance": 0.92,
            "retrieved_at": items[0]["retrieved_at"],
        }
    ]
    assert "title" not in items[0]


@pytest.mark.asyncio
async def test_cognia_relevance_score_is_not_assumed_to_be_probability_range(monkeypatch):
    monkeypatch.setattr(settings, "COGNIA_KNOWLEDGE_BASE_IDS", [10])
    monkeypatch.setattr(rag_module, "CogniaClient", FakeCogniaClient)
    FakeCogniaClient.search_payload = {
        "items": [
            {
                "rank": 1,
                "relevanceScore": 7.5,
                "knowledgeBaseId": 10,
                "knowledgeId": 1,
                "revisionId": 2,
                "revisionNumber": 1,
                "chunkId": 3,
                "chunkText": "provider-defined retrieval relevance",
            }
        ]
    }

    items = await KnowledgeRAGService().search("query")
    assert items[0]["relevance"] == 7.5
    assert await KnowledgeRAGService().search("query", min_similarity=8.0) == []


@pytest.mark.asyncio
async def test_cognia_contract_error_on_missing_traceability(monkeypatch):
    monkeypatch.setattr(settings, "COGNIA_KNOWLEDGE_BASE_IDS", [10])
    monkeypatch.setattr(rag_module, "CogniaClient", FakeCogniaClient)
    FakeCogniaClient.search_payload = {
        "items": [
            {
                "relevanceScore": 0.9,
                "knowledgeBaseId": 10,
                "knowledgeId": 1,
                "revisionId": 2,
                "revisionNumber": 1,
                "chunkText": "missing chunk id",
            }
        ]
    }

    with pytest.raises(CogniaContractError, match="cognia_search_item_missing:chunkId"):
        await KnowledgeRAGService().search("query")


@pytest.mark.asyncio
async def test_cognia_errors_propagate_and_do_not_fallback_to_local_db(monkeypatch):
    monkeypatch.setattr(settings, "COGNIA_KNOWLEDGE_BASE_IDS", [10])
    monkeypatch.setattr(rag_module, "CogniaClient", FakeCogniaClient)
    FakeCogniaClient.raised = CogniaAPIError(503, "SEARCH_INDEX_UNAVAILABLE")

    with pytest.raises(CogniaAPIError, match="SEARCH_INDEX_UNAVAILABLE"):
        await KnowledgeRAGService().search("query")



def test_cognia_service_exposes_no_local_rag_api():
    service = KnowledgeRAGService()
    assert not hasattr(service, "add_document")
    assert not hasattr(service, "get_all_documents")
    assert not hasattr(service, "_search_local")


@pytest.mark.asyncio
async def test_context_generation_uses_configured_profile(monkeypatch):
    monkeypatch.setattr(settings, "COGNIA_CONTEXT_PROFILE_ID", 501)
    monkeypatch.setattr(rag_module, "CogniaClient", FakeCogniaClient)

    result = await KnowledgeRAGService().generate_context(
        "collect safe runbook context",
        subject={"namespace": "service", "externalSubjectId": "payments"},
    )

    assert result["isSufficient"] is False
    assert result["context_profile_id"] == 501
    assert result["subject"] == {"namespace": "service", "externalSubjectId": "payments"}
