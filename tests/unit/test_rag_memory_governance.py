import pytest

from apps.memory_service import OperationalMemoryService
from apps.rag_service import KnowledgeRAGService
from domain.contracts.config import settings


def test_rag_rejects_non_allowlisted_source_type():
    with pytest.raises(ValueError, match="knowledge_source_type_not_allowlisted"):
        KnowledgeRAGService._govern_metadata({"source_type": "random_web", "owner": "ops"}, "1")


def test_rag_production_requires_owner_and_version(monkeypatch):
    monkeypatch.setattr(settings, "APP_ENV", "production")
    monkeypatch.setattr(settings, "KNOWLEDGE_REQUIRE_GOVERNANCE_PRODUCTION", True)
    with pytest.raises(ValueError, match="knowledge_owner_required"):
        KnowledgeRAGService._govern_metadata({"source_type": "runbook"}, "1")
    with pytest.raises(ValueError, match="knowledge_version_required"):
        KnowledgeRAGService._govern_metadata({"source_type": "runbook", "owner": "sre"}, None)


def test_rag_acl_defaults_to_internal():
    meta = KnowledgeRAGService._govern_metadata({"source_type": "runbook", "owner": "sre"}, "1")
    assert meta["namespace"] == "knowledge"
    assert meta["acl"] == ["internal"]
    assert KnowledgeRAGService._acl_allowed(meta, ["internal"])
    assert not KnowledgeRAGService._acl_allowed(meta, ["external"])


@pytest.mark.asyncio
async def test_memory_rejects_inconclusive_or_missing_outcome():
    service = OperationalMemoryService(db=None)  # validation happens before DB access
    with pytest.raises(ValueError, match="memory_requires_conclusive_verification"):
        await service.add_entry("pattern", {}, None, None, "inconclusive", "unknown")
    with pytest.raises(ValueError, match="memory_requires_outcome"):
        await service.add_entry("pattern", {}, None, None, "success", None)
