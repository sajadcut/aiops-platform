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


def test_authoritative_docs_do_not_advertise_a_second_rag():
    docs = [
        "README.md",
        "MASTER.md",
        "PRODUCTION_ACCEPTANCE.md",
        "FINAL_ACCEPTANCE_REPORT.md",
        "docs/PROJECT_STATE.md",
        "docs/PRODUCTION_ACCEPTANCE_MATRIX.md",
        "docs/master/IMPLEMENTATION_STATUS.md",
        "docs/COGNIA_INTEGRATION.md",
        "docs/adr/ADR-018-COGNIA-GOVERNED-RAG.md",
    ]
    forbidden_phrases = [
        "Local Knowledge pgvector",
        "local PostgreSQL/pgvector Knowledge remains",
        "development/test compatibility only",
        "local `knowledge_documents`/pgvector path remains",
        "local Knowledge pgvector only fixture",
        "local Knowledge فقط dev/test compatibility است",
        "legacy provider selector=cognia",
        "retired local Knowledge RAG",
        "embedding service for Knowledge RAG and Memory",
    ]
    for doc in docs:
        text = Path(doc).read_text(encoding="utf-8")
        for phrase in forbidden_phrases:
            assert phrase not in text, f"{doc} advertises a retired alternate RAG: {phrase}"


def test_authoritative_docs_state_cognia_only_boundary():
    readme = Path("README.md").read_text(encoding="utf-8")
    master = Path("MASTER.md").read_text(encoding="utf-8")
    project_state = Path("docs/PROJECT_STATE.md").read_text(encoding="utf-8")

    assert "Cognia is the only Governed Knowledge RAG in development, test and production" in readme
    assert "Cognia تنها Knowledge RAG پروژه" in master
    assert "Cognia is the only RAG for governed organizational knowledge in development, test and production" in project_state
