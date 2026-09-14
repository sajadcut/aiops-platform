from pathlib import Path


def read(path: str) -> str:
    return Path(path).read_text(encoding="utf-8")


def test_base_migration_creates_canonical_incident_tables():
    text = read("database/migrations/versions/34ec6bd70cb3_initial_migration_incident_evidence_.py")
    assert '"incidents"' in text
    assert '"evidences"' in text
    assert '"findings"' in text
    assert "pass" not in text


def test_operational_migration_references_incidents_id_and_does_not_create_shadow_incident_tables():
    text = read("database/migrations/versions/f1a2b3c4d5e6_add_operational_persistence.py")
    assert "REFERENCES incidents(id)" in text
    assert "incident_evidence" not in text
    assert "incident_findings" not in text
    assert "incident_id UUID PRIMARY KEY" not in text.split("workflow_checkpoints")[0]


def test_approval_consumed_migration_exists():
    text = read("database/migrations/versions/f2b3c4d5e6f7_approval_consumed_state.py")
    assert "consumed" in text
    assert 'down_revision: Union[str, Sequence[str], None] = "f1a2b3c4d5e6"' in text


def test_cognia_only_migration_retires_local_knowledge_vector_search():
    text = read("database/migrations/versions/c3d4e5f6a7b8_retire_local_knowledge_rag.py")
    assert 'op.rename_table("knowledge_documents", "legacy_knowledge_documents_archive")' in text
    assert 'op.drop_column("legacy_knowledge_documents_archive", "embedding")' in text
    assert 'down_revision: Union[str, Sequence[str], None] = "f2b3c4d5e6f7"' in text
