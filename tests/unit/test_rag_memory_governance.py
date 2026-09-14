import pytest

from apps.memory_service import OperationalMemoryService
from knowledge.retrieval_contract import validate_retrieval


def _cognia_item():
    return {
        "source_id": "cognia:10:20:30:40",
        "provider": "cognia",
        "relevance": 0.9,
        "retrieved_at": "2026-09-14T00:00:00+00:00",
        "knowledge_base_id": 10,
        "knowledge_id": 20,
        "revision_id": 30,
        "revision_number": 2,
        "chunk_id": 40,
        "version": "2",
        "content": "governed knowledge",
    }


def test_rag_retrieval_contract_accepts_only_cognia():
    assert validate_retrieval(_cognia_item())
    local = _cognia_item()
    local["provider"] = "postgresql"
    assert not validate_retrieval(local)


@pytest.mark.asyncio
async def test_memory_rejects_inconclusive_or_missing_outcome():
    service = OperationalMemoryService(db=None)  # validation happens before DB access
    with pytest.raises(ValueError, match="memory_requires_conclusive_verification"):
        await service.add_entry("pattern", {}, None, None, "inconclusive", "unknown")
    with pytest.raises(ValueError, match="memory_requires_outcome"):
        await service.add_entry("pattern", {}, None, None, "success", None)
