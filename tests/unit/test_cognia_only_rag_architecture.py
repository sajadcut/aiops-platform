from pathlib import Path


def _join(*parts: str) -> str:
    return "".join(parts)


def test_cognia_is_the_only_rag_runtime_contract():
    env = Path(".env.example").read_text(encoding="utf-8")
    config = Path("domain/contracts/config.py").read_text(encoding="utf-8")
    rag = Path("apps/rag_service/__init__.py").read_text(encoding="utf-8")
    models = Path("domain/models.py").read_text(encoding="utf-8")
    pgvector = Path("apps/database/pgvector_contract.py").read_text(encoding="utf-8")

    provider_selector = _join("KNOWLEDGE_", "PROVIDER")
    retired_provider = _join("local_", "pgvector")
    retired_model = _join("Knowledge", "Document")
    assert provider_selector not in env
    assert provider_selector not in config
    assert retired_provider not in rag
    assert retired_model not in models
    assert "knowledge_documents" not in pgvector
    assert "memory_entries" in pgvector
    assert "CogniaClient" in rag


def test_historical_local_knowledge_table_is_retired_without_vector_retrieval():
    migration = Path("database/migrations/versions/c3d4e5f6a7b8_retire_local_knowledge_rag.py").read_text(encoding="utf-8")
    assert "legacy_knowledge_documents_archive" in migration
    assert 'drop_column("legacy_knowledge_documents_archive", "embedding")' in migration
