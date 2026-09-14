from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def write(path: str, content: str) -> None:
    (ROOT / path).write_text(content, encoding="utf-8")


def replace_required(path: str, old: str, new: str) -> None:
    text = read(path)
    if old not in text:
        raise RuntimeError(f"required marker not found in {path}: {old[:120]!r}")
    write(path, text.replace(old, new, 1))


def replace_all(path: str, old: str, new: str) -> None:
    text = read(path)
    if old in text:
        write(path, text.replace(old, new))


def regex_required(path: str, pattern: str, replacement: str, flags: int = re.S) -> None:
    text = read(path)
    updated, count = re.subn(pattern, replacement, text, count=1, flags=flags)
    if count != 1:
        raise RuntimeError(f"required regex marker not found in {path}: {pattern[:120]!r}")
    write(path, updated)


# ---------------------------------------------------------------------------
# Runtime configuration: Cognia is the only Knowledge RAG provider everywhere.
# ---------------------------------------------------------------------------
replace_required(
    ".env.example",
    '''# Governed Knowledge RAG. Cognia is mandatory/canonical in Production.\n# This non-secret development template uses local_pgvector so a clean checkout\n# can run without real Cognia credentials; production validation rejects it.\nKNOWLEDGE_PROVIDER=local_pgvector\nKNOWLEDGE_ALLOWED_SOURCE_TYPES=["runbook","sop","architecture","service_catalog","operations_standard","troubleshooting"]\nKNOWLEDGE_REQUIRE_GOVERNANCE_PRODUCTION=True\n''',
    '''# Governed Knowledge RAG. Cognia is the only RAG provider in every environment.\n# A clean development/test checkout may leave Cognia connection values empty;\n# retrieval then reports a typed Cognia misconfiguration instead of falling back.\n''',
)

config_path = "domain/contracts/config.py"
replace_required(
    config_path,
    '''    KNOWLEDGE_PROVIDER: str = Field(...)\n    KNOWLEDGE_ALLOWED_SOURCE_TYPES: List[str] = Field(...)\n    KNOWLEDGE_REQUIRE_GOVERNANCE_PRODUCTION: bool = Field(...)\n''',
    "",
)
regex_required(
    config_path,
    r'''\n    @field_validator\("KNOWLEDGE_PROVIDER"\)\n    @classmethod\n    def validate_knowledge_provider\(cls, value: str\) -> str:\n        normalized = str\(value\)\.strip\(\)\.lower\(\)\n        if normalized not in \{"local_pgvector", "cognia"\}:\n            raise ValueError\("KNOWLEDGE_PROVIDER must be local_pgvector or cognia"\)\n        return normalized\n''',
    "\n",
)
regex_required(
    config_path,
    r'''    @model_validator\(mode="after"\)\n    def validate_cognia_contract\(self\) -> "Settings":.*?        return self\n\n''',
    '''    @model_validator(mode="after")\n    def validate_cognia_contract(self) -> "Settings":\n        if self.COGNIA_TIMEOUT_SECONDS <= 0:\n            raise ValueError("COGNIA_TIMEOUT_SECONDS must be positive")\n        if self.COGNIA_CONTEXT_PROFILE_ID is not None and self.COGNIA_CONTEXT_PROFILE_ID <= 0:\n            raise ValueError("COGNIA_CONTEXT_PROFILE_ID must be positive when configured")\n        if self.COGNIA_CLIENT_APPLICATION_ID is not None and self.COGNIA_CLIENT_APPLICATION_ID <= 0:\n            raise ValueError("COGNIA_CLIENT_APPLICATION_ID must be positive when configured")\n\n        # Cognia is the only Knowledge RAG provider. Development/test may load the\n        # tracked non-secret template without real Cognia credentials; any attempted\n        # retrieval remains explicitly misconfigured rather than using another RAG.\n        if self.APP_ENV == "production":\n            missing = [\n                name\n                for name, value in {\n                    "COGNIA_BASE_URL": self.COGNIA_BASE_URL,\n                    "COGNIA_CLIENT_ID": self.COGNIA_CLIENT_ID,\n                    "COGNIA_CLIENT_SECRET": self.COGNIA_CLIENT_SECRET,\n                }.items()\n                if not str(value or "").strip()\n            ]\n            if not self.COGNIA_KNOWLEDGE_BASE_IDS:\n                missing.append("COGNIA_KNOWLEDGE_BASE_IDS")\n            if missing:\n                raise ValueError("Cognia RAG requires: " + ", ".join(missing))\n            if urlparse(str(self.COGNIA_BASE_URL or "")).scheme != "https":\n                raise ValueError("COGNIA_BASE_URL must use HTTPS in production")\n            if not self.COGNIA_TLS_VERIFY:\n                raise ValueError("COGNIA_TLS_VERIFY must be enabled in production")\n        return self\n\n''',
)

# ---------------------------------------------------------------------------
# Cognia-only RAG service. PostgreSQL is not a Knowledge retrieval provider.
# ---------------------------------------------------------------------------
write(
    "apps/rag_service/__init__.py",
    '''from datetime import datetime, timezone\nfrom typing import Any, Dict, List, Optional\n\nfrom domain.contracts.config import settings\nfrom domain.contracts.logging import logger\nfrom integrations.cognia import CogniaClient, CogniaContractError\nfrom knowledge.retrieval_contract import validate_retrieval\n\n\nclass KnowledgeRAGService:\n    """Cognia-only governed Knowledge RAG boundary.\n\n    Cognia owns Knowledge Base permissions, Knowledge/Revision lifecycle, Scope,\n    Search and Context policy. PostgreSQL/pgvector is reserved for Operational\n    Memory and is never a fallback Knowledge RAG provider.\n    """\n\n    async def search(\n        self,\n        query: str,\n        limit: int = 5,\n        min_similarity: float = 0.5,\n        access_scopes: Optional[List[str]] = None,\n        scope_context: Optional[Dict[str, Any]] = None,\n    ) -> List[Dict[str, Any]]:\n        # access_scopes is retained only for call compatibility during migration;\n        # Cognia is authoritative for KB grants and Scope authorization.\n        del access_scopes\n        if not query.strip():\n            return []\n        if limit <= 0:\n            raise ValueError("knowledge_search_limit_must_be_positive")\n        if not 0 <= min_similarity <= 1:\n            raise ValueError("knowledge_min_relevance_must_be_between_0_and_1")\n        return await self._search_cognia(\n            query,\n            limit=limit,\n            min_relevance=min_similarity,\n            scope_context=scope_context,\n        )\n\n    async def _search_cognia(\n        self,\n        query: str,\n        *,\n        limit: int,\n        min_relevance: float,\n        scope_context: Optional[Dict[str, Any]],\n    ) -> List[Dict[str, Any]]:\n        retrieved_at = datetime.now(timezone.utc).isoformat()\n        async with CogniaClient() as client:\n            payload = await client.search(\n                query,\n                knowledge_base_ids=settings.COGNIA_KNOWLEDGE_BASE_IDS,\n                limit=limit,\n                scope_context=scope_context,\n            )\n\n        documents: List[Dict[str, Any]] = []\n        for raw in payload.get("items", []):\n            if not isinstance(raw, dict):\n                raise CogniaContractError("cognia_search_item_must_be_object")\n            required = (\n                "knowledgeBaseId",\n                "knowledgeId",\n                "revisionId",\n                "revisionNumber",\n                "chunkId",\n                "chunkText",\n                "relevanceScore",\n            )\n            missing = [key for key in required if raw.get(key) is None]\n            if missing:\n                raise CogniaContractError("cognia_search_item_missing:" + ",".join(missing))\n            try:\n                relevance = float(raw["relevanceScore"])\n            except (TypeError, ValueError) as exc:\n                raise CogniaContractError("cognia_relevance_score_invalid") from exc\n            if not 0 <= relevance <= 1:\n                raise CogniaContractError("cognia_relevance_score_out_of_range")\n            if relevance < min_relevance:\n                continue\n\n            knowledge_base_id = int(raw["knowledgeBaseId"])\n            knowledge_id = int(raw["knowledgeId"])\n            revision_id = int(raw["revisionId"])\n            revision_number = int(raw["revisionNumber"])\n            chunk_id = int(raw["chunkId"])\n            source_id = f"cognia:{knowledge_base_id}:{knowledge_id}:{revision_id}:{chunk_id}"\n            item: Dict[str, Any] = {\n                "id": source_id,\n                "source_id": source_id,\n                "provider": "cognia",\n                "source": "cognia",\n                "knowledge_base_id": knowledge_base_id,\n                "knowledge_id": knowledge_id,\n                "revision_id": revision_id,\n                "revision_number": revision_number,\n                "version": str(revision_number),\n                "chunk_id": chunk_id,\n                "chunk_index": raw.get("chunkIndex"),\n                "content": str(raw["chunkText"]),\n                "start_offset": raw.get("startOffset"),\n                "end_offset": raw.get("endOffset"),\n                "approximate_token_count": raw.get("approximateTokenCount"),\n                "knowledge_type": raw.get("knowledgeType"),\n                "scope": raw.get("scope"),\n                "rank": raw.get("rank"),\n                "relevance": relevance,\n                "retrieved_at": retrieved_at,\n            }\n            if not validate_retrieval(item):\n                raise CogniaContractError("cognia_retrieval_contract_invalid")\n            documents.append(item)\n            if len(documents) >= limit:\n                break\n\n        logger.info(\n            "cognia_rag_search_completed",\n            count=len(documents),\n            knowledge_base_count=len(settings.COGNIA_KNOWLEDGE_BASE_IDS),\n        )\n        return documents\n\n    @staticmethod\n    def _ensure_configured_kb(knowledge_base_id: int) -> int:\n        kb_id = int(knowledge_base_id)\n        if kb_id <= 0:\n            raise ValueError("cognia_knowledge_base_id_must_be_positive")\n        if kb_id not in settings.COGNIA_KNOWLEDGE_BASE_IDS:\n            raise ValueError("cognia_knowledge_base_not_configured_for_aiops")\n        return kb_id\n\n    async def register_knowledge(\n        self,\n        *,\n        knowledge_base_id: int,\n        title: str,\n        content: str,\n        scope: Dict[str, Any],\n        knowledge_type: str = "text",\n        tag_ids: Optional[List[int]] = None,\n        category_ids: Optional[List[int]] = None,\n        metadata: Optional[Dict[str, str]] = None,\n        idempotency_key: Optional[str] = None,\n    ) -> Dict[str, Any]:\n        kb_id = self._ensure_configured_kb(knowledge_base_id)\n        async with CogniaClient() as client:\n            return await client.register_knowledge(\n                knowledge_base_id=kb_id,\n                title=title,\n                content=content,\n                scope=scope,\n                knowledge_type=knowledge_type,\n                tag_ids=tag_ids,\n                category_ids=category_ids,\n                metadata=metadata,\n                idempotency_key=idempotency_key,\n            )\n\n    async def create_revision(\n        self,\n        *,\n        knowledge_base_id: int,\n        knowledge_id: int,\n        expected_current_candidate_revision_id: Optional[int],\n        title: str,\n        content: str,\n        tag_ids: Optional[List[int]] = None,\n        category_ids: Optional[List[int]] = None,\n        metadata: Optional[Dict[str, str]] = None,\n    ) -> Dict[str, Any]:\n        kb_id = self._ensure_configured_kb(knowledge_base_id)\n        async with CogniaClient() as client:\n            return await client.create_revision(\n                knowledge_base_id=kb_id,\n                knowledge_id=knowledge_id,\n                expected_current_candidate_revision_id=expected_current_candidate_revision_id,\n                title=title,\n                content=content,\n                tag_ids=tag_ids,\n                category_ids=category_ids,\n                metadata=metadata,\n            )\n\n    async def get_processing_status(\n        self, *, knowledge_base_id: int, knowledge_id: int, revision_id: int\n    ) -> Dict[str, Any]:\n        kb_id = self._ensure_configured_kb(knowledge_base_id)\n        async with CogniaClient() as client:\n            return await client.get_processing_status(\n                knowledge_base_id=kb_id,\n                knowledge_id=knowledge_id,\n                revision_id=revision_id,\n            )\n\n    async def generate_context(\n        self,\n        task: str,\n        *,\n        subject: Optional[Dict[str, str]] = None,\n        context_profile_id: Optional[int] = None,\n    ) -> Dict[str, Any]:\n        profile_id = context_profile_id or settings.COGNIA_CONTEXT_PROFILE_ID\n        if profile_id is None:\n            raise RuntimeError("cognia_context_profile_id_not_configured")\n        async with CogniaClient() as client:\n            return await client.generate_context(\n                task,\n                context_profile_id=profile_id,\n                subject=subject,\n            )\n''',
)

write(
    "knowledge/retrieval_contract.py",
    '''from typing import Any, Dict\n\nBASE_REQUIRED = ("source_id", "provider", "relevance", "retrieved_at")\nCOGNIA_REQUIRED = (\n    "knowledge_base_id",\n    "knowledge_id",\n    "revision_id",\n    "revision_number",\n    "chunk_id",\n    "version",\n    "content",\n)\n\n\ndef validate_retrieval(item: Dict[str, Any]) -> bool:\n    if not all(key in item for key in BASE_REQUIRED):\n        return False\n    if str(item.get("provider") or "").strip().lower() != "cognia":\n        return False\n    try:\n        relevance = float(item.get("relevance"))\n    except (TypeError, ValueError):\n        return False\n    if not 0.0 <= relevance <= 1.0:\n        return False\n    return all(key in item and item.get(key) is not None for key in COGNIA_REQUIRED)\n''',
)

write(
    "apps/database/pgvector_contract.py",
    '''from __future__ import annotations\n\nfrom typing import Any, Dict\n\nfrom sqlalchemy import text\nfrom sqlalchemy.ext.asyncio import AsyncSession\n\n\nasync def validate_pgvector(session: AsyncSession, expected_dimension: int) -> Dict[str, Any]:\n    """Validate pgvector strictly for Operational Memory, never Knowledge RAG."""\n    extension = (await session.execute(text("SELECT extversion FROM pg_extension WHERE extname='vector'"))).scalar_one_or_none()\n    if not extension:\n        raise RuntimeError("pgvector_extension_missing")\n\n    dimension = (await session.execute(text(\n        """SELECT atttypmod FROM pg_attribute\n        WHERE attrelid='memory_entries'::regclass\n          AND attname='embedding' AND atttypid='vector'::regtype"""\n    ))).scalar_one_or_none()\n    if dimension is None:\n        raise RuntimeError("memory_embedding_vector_column_missing")\n    if int(dimension) != int(expected_dimension):\n        raise RuntimeError(f"memory_embedding_dimension_mismatch:{dimension}!={expected_dimension}")\n\n    return {\n        "extension": extension,\n        "dimension": int(dimension),\n        "expected_dimension": int(expected_dimension),\n        "scope": "operational_memory",\n        "valid": True,\n    }\n''',
)

# Orchestrator: always query Cognia, with typed degradation and no DB/provider branch.
orch = read("apps/orchestrator/e2e_graph.py")
orch = orch.replace("settings.KNOWLEDGE_PROVIDER", '"cognia"')
orch = orch.replace('        can_query_knowledge = "cognia" == "cognia" or self.db is not None\n', "")
orch = orch.replace("        elif can_query_knowledge:\n", "        else:\n", 1)
orch = orch.replace("KnowledgeRAGService(self.db).search", "KnowledgeRAGService().search")
legacy_else = '''        else:\n            state["knowledge_status"] = {\n                "provider": "cognia",\n                "status": "misconfigured",\n                "code": "local_pgvector_database_session_required",\n                "count": 0,\n            }\n\n'''
if legacy_else in orch:
    orch = orch.replace(legacy_else, "", 1)
write("apps/orchestrator/e2e_graph.py", orch)

# ORM: Knowledge is not a PostgreSQL runtime model. pgvector remains for MemoryEntry.
models = read("domain/models.py")
models = models.replace(
    "مدل‌های canonical داده برای Incident، Evidence، Finding، RAG و Memory.",
    "مدل‌های canonical داده برای Incident، Evidence، Finding و Operational Memory.",
)
models = models.replace(
    "Knowledge و Operational Memory نیز دو namespace جدا هستند.",
    "Governed Knowledge در Cognia است و Operational Memory در PostgreSQL/pgvector باقی می‌ماند.",
)
models = re.sub(
    r'''\n# Knowledge RAG و Operational Memory عمداً جدا هستند:.*?\n\nclass MemoryEntry\(Base\):''',
    '''\n# Governed Knowledge RAG فقط در Cognia نگهداری/بازیابی می‌شود. PostgreSQL هیچ\n# Knowledge ORM فعال ندارد؛ pgvector اینجا فقط برای Operational Memory است.\nclass MemoryEntry(Base):''',
    models,
    count=1,
    flags=re.S,
)
write("domain/models.py", models)
replace_required(
    "database/migrations/env.py",
    "from domain.models import Incident, Evidence, Finding, KnowledgeDocument, MemoryEntry  # noqa: F401",
    "from domain.models import Incident, Evidence, Finding, MemoryEntry  # noqa: F401",
)

# Historical local Knowledge data is preserved as a non-RAG archive; the vector
# column is removed so the final schema cannot accidentally serve a second RAG.
migration_path = ROOT / "database/migrations/versions/c3d4e5f6a7b8_retire_local_knowledge_rag.py"
migration_path.write_text(
    '''"""Retire local PostgreSQL Knowledge RAG while preserving historical content.\n\nRevision ID: c3d4e5f6a7b8\nRevises: f2b3c4d5e6f7\n"""\nfrom typing import Sequence, Union\n\nfrom alembic import op\n\nrevision: str = "c3d4e5f6a7b8"\ndown_revision: Union[str, Sequence[str], None] = "f2b3c4d5e6f7"\nbranch_labels: Union[str, Sequence[str], None] = None\ndepends_on: Union[str, Sequence[str], None] = None\n\n\ndef upgrade() -> None:\n    # Preserve any pre-Cognia content for controlled migration/audit, but remove\n    # its vector-search capability and active Knowledge table name. Runtime code\n    # has no ORM/retriever for this archive.\n    op.rename_table("knowledge_documents", "legacy_knowledge_documents_archive")\n    op.drop_column("legacy_knowledge_documents_archive", "embedding")\n    op.execute(\n        "COMMENT ON TABLE legacy_knowledge_documents_archive IS "\n        "'Legacy pre-Cognia content archive; not an active RAG source'"\n    )\n\n\ndef downgrade() -> None:\n    # Downgrade restores only schema compatibility; historical embeddings are not\n    # recreated because they are no longer authoritative after Cognia migration.\n    op.execute(\n        "ALTER TABLE legacy_knowledge_documents_archive "\n        "ADD COLUMN embedding vector(1536) NULL"\n    )\n    op.rename_table("legacy_knowledge_documents_archive", "knowledge_documents")\n''',
    encoding="utf-8",
)

# ---------------------------------------------------------------------------
# Tests: enforce Cognia-only provider semantics.
# ---------------------------------------------------------------------------
write(
    "tests/unit/test_centralized_config.py",
    '''from pathlib import Path\n\nimport pytest\nfrom pydantic import ValidationError\n\nfrom domain.contracts.config import Settings, settings\n\n\ndef _template_keys() -> set[str]:\n    keys: set[str] = set()\n    for raw_line in Path(".env.example").read_text(encoding="utf-8").splitlines():\n        line = raw_line.strip()\n        if not line or line.startswith("#") or "=" not in line:\n            continue\n        keys.add(line.split("=", 1)[0])\n    return keys\n\n\ndef _template_values() -> dict[str, str]:\n    values: dict[str, str] = {}\n    for raw_line in Path(".env.example").read_text(encoding="utf-8").splitlines():\n        line = raw_line.strip()\n        if not line or line.startswith("#") or "=" not in line:\n            continue\n        key, value = line.split("=", 1)\n        values[key] = value.strip()\n    return values\n\n\ndef _settings_data(**overrides):\n    data = settings.model_dump()\n    data.update(overrides)\n    return data\n\n\ndef test_canonical_env_template_covers_every_settings_field():\n    env_keys = _template_keys()\n    settings_keys = set(Settings.model_fields)\n    assert settings_keys <= env_keys, f"Missing .env.example keys: {sorted(settings_keys - env_keys)}"\n\n\ndef test_populated_env_is_ignored_and_template_is_tracked_contract():\n    gitignore = Path(".gitignore").read_text(encoding="utf-8").splitlines()\n    assert ".env" in gitignore\n    assert "!.env.example" in gitignore\n    assert Path(".env.example").exists()\n\n\ndef test_settings_contains_no_runtime_defaults():\n    defaults = {\n        name: field.default\n        for name, field in Settings.model_fields.items()\n        if not field.is_required()\n    }\n    assert not defaults, f"Runtime defaults must live in .env.example, not config.py: {defaults}"\n\n\ndef test_loaded_settings_match_complete_contract():\n    for key in Settings.model_fields:\n        assert hasattr(settings, key)\n\n\ndef test_cognia_is_the_only_rag_and_template_has_no_provider_switch():\n    values = _template_values()\n    assert "KNOWLEDGE_PROVIDER" not in values\n    assert "KNOWLEDGE_ALLOWED_SOURCE_TYPES" not in values\n    assert "KNOWLEDGE_REQUIRE_GOVERNANCE_PRODUCTION" not in values\n    assert values["COGNIA_CLIENT_SECRET"] == ""\n    assert values["COGNIA_CLIENT_ID"] == ""\n    assert values["COGNIA_BASE_URL"] == ""\n    assert values["COGNIA_CLIENT_APPLICATION_ID"] == ""\n\n\ndef test_production_cognia_requires_machine_identity_and_explicit_kbs():\n    with pytest.raises(ValidationError, match="Cognia RAG requires"):\n        Settings(\n            _env_file=None,\n            **_settings_data(\n                APP_ENV="production",\n                COGNIA_BASE_URL="https://cognia.test",\n                COGNIA_CLIENT_ID="",\n                COGNIA_CLIENT_SECRET="",\n                COGNIA_KNOWLEDGE_BASE_IDS=[],\n                COGNIA_TLS_VERIFY=True,\n            ),\n        )\n\n\ndef test_production_cognia_requires_https_and_tls_verification():\n    base = _settings_data(\n        APP_ENV="production",\n        COGNIA_CLIENT_ID="app-id",\n        COGNIA_CLIENT_SECRET="test-only-secret",\n        COGNIA_KNOWLEDGE_BASE_IDS=[10],\n    )\n    with pytest.raises(ValidationError, match="COGNIA_BASE_URL must use HTTPS"):\n        Settings(_env_file=None, **{**base, "COGNIA_BASE_URL": "http://cognia.test", "COGNIA_TLS_VERIFY": True})\n\n    with pytest.raises(ValidationError, match="COGNIA_TLS_VERIFY must be enabled"):\n        Settings(_env_file=None, **{**base, "COGNIA_BASE_URL": "https://cognia.test", "COGNIA_TLS_VERIFY": False})\n\n\ndef test_production_cognia_accepts_machine_identity_and_explicit_kbs():\n    configured = Settings(\n        _env_file=None,\n        **_settings_data(\n            APP_ENV="production",\n            COGNIA_BASE_URL="https://cognia.test",\n            COGNIA_CLIENT_ID="app-id",\n            COGNIA_CLIENT_SECRET="test-only-secret",\n            COGNIA_KNOWLEDGE_BASE_IDS=[10, 20],\n            COGNIA_TLS_VERIFY=True,\n        ),\n    )\n    assert configured.COGNIA_KNOWLEDGE_BASE_IDS == [10, 20]\n\n\ndef test_optional_cognia_numeric_ids_parse_empty_template_values_as_none():\n    values = _settings_data(COGNIA_CLIENT_APPLICATION_ID="", COGNIA_CONTEXT_PROFILE_ID="")\n    configured = Settings(_env_file=None, **values)\n    assert configured.COGNIA_CLIENT_APPLICATION_ID is None\n    assert configured.COGNIA_CONTEXT_PROFILE_ID is None\n\n\ndef test_alembic_does_not_bypass_centralized_settings():\n    source = Path("database/migrations/env.py").read_text(encoding="utf-8")\n    assert "os.getenv" not in source\n    assert "settings.ALEMBIC_DATABASE_URL" in source\n\n\ndef test_rate_limits_are_not_hardcoded_in_runtime_module():\n    source = Path("domain/contracts/rate_limit.py").read_text(encoding="utf-8")\n    assert "settings.API_RATE_LIMIT_PER_MINUTE" in source\n    assert "settings.RATE_LIMIT_STRICT_REQUESTS" in source\n    assert "settings.RATE_LIMIT_LOOSE_REQUESTS" in source\n    assert "settings.RATE_LIMIT_WINDOW_SECONDS" in source\n''',
)

write(
    "tests/unit/test_rag_memory_governance.py",
    '''import pytest\n\nfrom apps.memory_service import OperationalMemoryService\nfrom knowledge.retrieval_contract import validate_retrieval\n\n\ndef _cognia_item():\n    return {\n        "source_id": "cognia:10:20:30:40",\n        "provider": "cognia",\n        "relevance": 0.9,\n        "retrieved_at": "2026-09-14T00:00:00+00:00",\n        "knowledge_base_id": 10,\n        "knowledge_id": 20,\n        "revision_id": 30,\n        "revision_number": 2,\n        "chunk_id": 40,\n        "version": "2",\n        "content": "governed knowledge",\n    }\n\n\ndef test_rag_retrieval_contract_accepts_only_cognia():\n    assert validate_retrieval(_cognia_item())\n    local = _cognia_item()\n    local["provider"] = "postgresql"\n    assert not validate_retrieval(local)\n\n\n@pytest.mark.asyncio\nasync def test_memory_rejects_inconclusive_or_missing_outcome():\n    service = OperationalMemoryService(db=None)  # validation happens before DB access\n    with pytest.raises(ValueError, match="memory_requires_conclusive_verification"):\n        await service.add_entry("pattern", {}, None, None, "inconclusive", "unknown")\n    with pytest.raises(ValueError, match="memory_requires_outcome"):\n        await service.add_entry("pattern", {}, None, None, "success", None)\n''',
)

rag_test = read("tests/unit/test_cognia_rag_service.py")
rag_test = rag_test.replace('    monkeypatch.setattr(settings, "KNOWLEDGE_PROVIDER", "cognia")\n', "")
rag_test = rag_test.replace("KnowledgeRAGService(db=None)", "KnowledgeRAGService()")
rag_test = re.sub(
    r'''\n@pytest\.mark\.asyncio\nasync def test_legacy_local_authoring_is_blocked_for_cognia\(monkeypatch\):.*?(?=\n@pytest\.mark\.asyncio\nasync def test_context_generation_uses_configured_profile)''',
    '''\n\ndef test_cognia_service_exposes_no_local_rag_api():\n    service = KnowledgeRAGService()\n    assert not hasattr(service, "add_document")\n    assert not hasattr(service, "get_all_documents")\n    assert not hasattr(service, "_search_local")\n\n''',
    rag_test,
    count=1,
    flags=re.S,
)
write("tests/unit/test_cognia_rag_service.py", rag_test)

migration_test = read("tests/unit/test_migration_contract.py")
migration_test += '''\n\ndef test_cognia_only_migration_retires_local_knowledge_vector_search():\n    text = read("database/migrations/versions/c3d4e5f6a7b8_retire_local_knowledge_rag.py")\n    assert 'op.rename_table("knowledge_documents", "legacy_knowledge_documents_archive")' in text\n    assert 'op.drop_column("legacy_knowledge_documents_archive", "embedding")' in text\n    assert 'down_revision: Union[str, Sequence[str], None] = "f2b3c4d5e6f7"' in text\n'''
write("tests/unit/test_migration_contract.py", migration_test)

# Local Knowledge seeding is forbidden now that Cognia is the sole RAG.
seed = ROOT / "scripts/add_knowledge.py"
if seed.exists():
    seed.unlink()

# ---------------------------------------------------------------------------
# Database acceptance: pgvector validates Operational Memory only.
# ---------------------------------------------------------------------------
quality = read(".github/workflows/quality.yml")
quality = quality.replace(
    "Validate canonical schema pgvector and governance persistence",
    "Validate canonical schema Operational Memory pgvector and governance persistence",
)
quality = quality.replace(
    "required = {'incidents','evidences','findings','knowledge_documents','memory_entries','approvals','audit_events','workflow_checkpoints','runbooks'}",
    "required = {'incidents','evidences','findings','memory_entries','approvals','audit_events','workflow_checkpoints','runbooks','legacy_knowledge_documents_archive'}",
)
quality = quality.replace(
    "                  assert required <= tables, required - tables\n",
    "                  assert required <= tables, required - tables\n                  assert 'knowledge_documents' not in tables, 'local Knowledge RAG table must be retired'\n",
)
quality = quality.replace(
    "WHERE table_name IN ('knowledge_documents','memory_entries') AND column_name='embedding'",
    "WHERE table_name='memory_entries' AND column_name='embedding'",
)
quality = quality.replace(
    "assert len(vector_rows) == 2 and all(row[1] == 'vector' for row in vector_rows), vector_rows",
    "assert len(vector_rows) == 1 and vector_rows[0][1] == 'vector', vector_rows",
)
quality = quality.replace(
    "                  incident_id = uuid4()\n",
    "                  cur.execute(\"SELECT column_name FROM information_schema.columns WHERE table_name='legacy_knowledge_documents_archive'\")\n                  legacy_columns = {row[0] for row in cur.fetchall()}\n                  assert 'embedding' not in legacy_columns, legacy_columns\n                  incident_id = uuid4()\n",
)
quality = re.sub(
    r'''                  dimension = settings\.EMBEDDING_DIMENSION\n                  vector = "\[" \+ ","\.join\(\["0\.1"\] \* dimension\) \+ "\]"\n                  cur\.execute\(\n                      "INSERT INTO knowledge_documents .*?                  assert cur\.fetchone\(\)\[0\] == 0\.0''',
    '''                  dimension = settings.EMBEDDING_DIMENSION\n                  vector = "[" + ",".join(["0.1"] * dimension) + "]"\n                  cur.execute(\n                      "INSERT INTO memory_entries (id,pattern,symptoms,verification_result,outcome,embedding) VALUES (%s,%s,%s::json,%s,%s,%s::vector)",\n                      (uuid4(),'ci operational pattern','{}','success','verified recovery',vector),\n                  )\n                  cur.execute("SELECT embedding <=> %s::vector FROM memory_entries ORDER BY embedding <=> %s::vector LIMIT 1", (vector, vector))\n                  assert cur.fetchone()[0] == 0.0''',
    quality,
    count=1,
    flags=re.S,
)
quality = quality.replace("assert cur.fetchone()[0] == 'f2b3c4d5e6f7'", "assert cur.fetchone()[0] == 'c3d4e5f6a7b8'")
write(".github/workflows/quality.yml", quality)

# ---------------------------------------------------------------------------
# Architecture/docs: one RAG only. Historical PostgreSQL RAG is superseded.
# ---------------------------------------------------------------------------
replace_all(
    "docs/adr/DECISIONS.md",
    "**Decision:** pgvector Vector Search Layer اصلی Operational Memory و fixtureهای local development/test است. Governed Knowledge Production از Cognia استفاده می‌کند.",
    "**Decision:** pgvector فقط Vector Search Layer اصلی Operational Memory است. هیچ Knowledge RAG محلی در معماری فعال نیست؛ Cognia تنها RAG پروژه است.",
)
replace_all(
    "docs/adr/DECISIONS.md",
    "**Decision:** Historical MVP used PostgreSQL + pgvector behind a retrieval abstraction. Production Governed Knowledge is now Cognia; local pgvector Knowledge remains dev/test compatibility only.",
    "**Decision:** Historical MVP used PostgreSQL + pgvector behind a retrieval abstraction. این تصمیم superseded است؛ Cognia تنها Knowledge RAG در development، test و production است و مسیر local Knowledge retrieval وجود ندارد.",
)
replace_all(
    "docs/adr/DECISIONS.md",
    "**Decision:** Cognia مرجع اصلی Governed Knowledge RAG است.",
    "**Decision:** Cognia تنها Governed Knowledge RAG پروژه در همه environmentها است.",
)
replace_all(
    "docs/adr/DECISIONS.md",
    "**No fallback:** خطای Cognia نباید به Search موفق خالی یا fallback پنهان local pgvector تبدیل شود.",
    "**No fallback / no second RAG:** خطای Cognia نباید به Search موفق خالی یا هر Knowledge retriever دیگری تبدیل شود؛ RAG دوم در پروژه وجود ندارد.",
)

replace_all(
    "docs/COGNIA_INTEGRATION.md",
    "Cognia is the canonical Governed Knowledge RAG.",
    "Cognia is the only Governed Knowledge RAG in aiops-platform across development, test and production.",
)
replace_all(
    "docs/COGNIA_INTEGRATION.md",
    "There is no Cognia → local Knowledge fallback in Production.",
    "There is no alternate/local Knowledge RAG or Cognia fallback in any environment.",
)
replace_all(
    "docs/COGNIA_INTEGRATION.md",
    "do not trigger local pgvector fallback",
    "do not trigger any alternate RAG fallback",
)

# MASTER 2.5 makes the decision unambiguous.
master = read("MASTER.md")
master = master.replace("**2.4 - Cognia Governed Knowledge RAG**", "**2.5 - Cognia-Only Knowledge RAG**", 1)
master = master.replace(
    "**Cognia مرجع اصلی و canonical برای Governed Knowledge RAG است؛ local PostgreSQL/pgvector مسیر Production Knowledge نیست.**",
    "**Cognia تنها Knowledge RAG پروژه در development، test و production است؛ PostgreSQL/pgvector فقط Operational Memory است و هیچ Knowledge retriever محلی یا fallback دیگری مجاز نیست.**",
)
master = master.replace(
    "**PostgreSQL + pgvector** لایه Semantic Retrieval برای Operational Memory است؛ local Knowledge pgvector فقط fixture توسعه/تست و سازگاری تاریخی است.",
    "**PostgreSQL + pgvector** فقط لایه Semantic Retrieval برای Operational Memory است و هیچ نقش Knowledge RAG ندارد.",
)
master = master.replace(
    "در خطای Cognia، سیستم حق fallback پنهان به local Knowledge ندارد؛",
    "در خطای Cognia، سیستم حق fallback به هیچ Knowledge RAG دیگری ندارد؛",
)
master = master.replace(
    "**pgvector** Vector Search لایه Operational Memory را فراهم می‌کند. جدول/مدل local Knowledge موجود فقط برای fixtureهای توسعه/تست و migration compatibility نگه داشته می‌شود و System of Record دانش Production نیست.",
    "**pgvector** فقط Vector Search لایه Operational Memory را فراهم می‌کند. مدل/جدول فعال Knowledge در PostgreSQL وجود ندارد؛ محتوای تاریخی pre-Cognia صرفاً در archive بدون embedding/retrieval نگهداری می‌شود تا مهاجرت داده قابل کنترل باشد.",
)
master = master.replace(
    "| KnowledgeDocument | id, source, title, version, metadata, chunk_refs, embedding_model, embedding_status, status |",
    "| CogniaKnowledgeChunkRef | knowledge_base_id, knowledge_id, revision_id, revision_number, chunk_id, scope, relevance, retrieved_at |",
)
master = master.replace(
    "| **2.4** | **تثبیت Cognia به‌عنوان canonical Governed Knowledge RAG؛ محدودکردن pgvector به Operational Memory/dev-test Knowledge؛ تعریف Machine Auth، Scope، Search/Context، authoring lifecycle و no-hidden-fallback** | **هم‌راستا کردن SSoT با قرارداد رسمی Cognia و تصمیم قطعی پروژه** |",
    "| **2.4** | **تثبیت Cognia به‌عنوان canonical Governed Knowledge RAG و تعریف Machine Auth، Scope، Search/Context، authoring lifecycle و no-hidden-fallback** | **هم‌راستا کردن SSoT با قرارداد رسمی Cognia** |\n| **2.5** | **حذف کامل provider-switch و local Knowledge RAG از runtime/CI؛ Cognia تنها RAG در همه environmentها؛ pgvector فقط Operational Memory؛ retire کردن Knowledge vector table به archive بدون embedding** | **اجرای تصمیم قطعی Cognia-only و حذف هر ambiguity درباره RAG دوم** |",
)
master = master.replace(
    "local Knowledge pgvector فقط fixture/compatibility غیرProduction است.",
    "هیچ local Knowledge RAG وجود ندارد؛ pgvector فقط Operational Memory است.",
)
master = master.replace(
    "Cognia canonical System of Record",
    "Cognia تنها System of Record و RAG boundary",
)
write("MASTER.md", master)

# Configuration docs: remove provider switch and local RAG semantics.
config_doc = read("docs/CONFIGURATION.md")
config_doc = config_doc.replace(
    "- governed production Knowledge is enabled but `KNOWLEDGE_PROVIDER` is not `cognia`;\n- Cognia is selected without Application Client credentials, an explicit positive KB allowlist, HTTPS or TLS verification;",
    "- Cognia RAG lacks Application Client credentials, an explicit positive KB allowlist, HTTPS or TLS verification;",
)
config_doc = re.sub(
    r'''## Governed Knowledge / Cognia boundary\n\n.*?\n## Configuration inventory''',
    '''## Governed Knowledge / Cognia boundary\n\nCognia is the **only** Knowledge RAG provider in every environment. There is no runtime provider selector and no PostgreSQL/pgvector Knowledge fallback. Development/test may leave Cognia connectivity placeholders empty so a clean checkout can import; any attempted RAG retrieval then produces an explicit typed Cognia misconfiguration.\n\n- Operational Memory remains separate in PostgreSQL + pgvector.\n- AIOps uses Cognia Application Client machine identity, never human credentials.\n- `COGNIA_KNOWLEDGE_BASE_IDS` is explicit on Search; Cognia remains authoritative for KB grants and Scope.\n- Search/index/dependency failures are provider failures, never empty-result fallback.\n- `COGNIA_CONTEXT_PROFILE_ID` remains optional because Context Generation is a separate Cognia capability.\n- The supplied sandpod guide uses HTTP; production AIOps still requires an approved HTTPS endpoint with TLS verification.\n\n## Configuration inventory''',
    config_doc,
    count=1,
    flags=re.S,
)
config_doc = config_doc.replace("Operational Memory + local development RAG", "Operational Memory")
config_doc = re.sub(r'''\n\| `KNOWLEDGE_PROVIDER` \|.*?\n\| `KNOWLEDGE_ALLOWED_SOURCE_TYPES`, `KNOWLEDGE_REQUIRE_GOVERNANCE_PRODUCTION` \|.*?\n''', "\n", config_doc, count=1)
config_doc = config_doc.replace(
    "`KNOWLEDGE_PROVIDER=local_pgvector`, ",
    "",
)
config_doc = config_doc.replace(
    "including `KNOWLEDGE_PROVIDER`, `COGNIA_BASE_URL`",
    "including `COGNIA_BASE_URL`",
)
write("docs/CONFIGURATION.md", config_doc)

# Status/acceptance/readme wording.
for path in [
    "README.md",
    "FINAL_ACCEPTANCE_REPORT.md",
    "PRODUCTION_ACCEPTANCE.md",
    "docs/PROJECT_STATE.md",
    "docs/PRODUCTION_ACCEPTANCE_MATRIX.md",
    "docs/master/IMPLEMENTATION_STATUS.md",
    "docs/CODEBASE_GUIDE_FA.md",
    "docs/CODE_SYMBOLS_FA.md",
    "docs/FILE_INDEX_FA.md",
]:
    p = ROOT / path
    if not p.exists():
        continue
    text = p.read_text(encoding="utf-8")
    replacements = {
        "canonical Cognia": "Cognia-only",
        "Cognia canonical": "Cognia-only",
        "canonical Governed Knowledge RAG": "only Governed Knowledge RAG",
        "canonical Cognia machine-auth/Search/Context/authoring contract": "Cognia-only machine-auth/Search/Context/authoring contract",
        "local Knowledge pgvector": "legacy pre-Cognia Knowledge archive",
        "local pgvector Knowledge": "legacy pre-Cognia Knowledge archive",
        "PostgreSQL+pgvector and governance": "Operational Memory PostgreSQL+pgvector and Cognia governance",
        "Knowledge RAG and Operational Memory remain separate and use PostgreSQL + pgvector.": "Knowledge RAG is Cognia-only; Operational Memory separately uses PostgreSQL + pgvector.",
        "`knowledge_documents`: RAG رسمی با metadata و `vector(1536)`.\n": "`legacy_knowledge_documents_archive`: محتوای تاریخی pre-Cognia بدون embedding/retrieval؛ RAG فعال نیست.\n",
        "KnowledgeDocument": "CogniaKnowledgeChunkRef",
    }
    for old, new in replacements.items():
        text = text.replace(old, new)
    p.write_text(text, encoding="utf-8")

# Generator descriptions must not regenerate old semantics.
generator = read("scripts/generate_file_index_fa.py")
generator = generator.replace(
    '"apps/database/": ("DB", "قرارداد/validation pgvector runtime", "startup/CI", "PostgreSQL", "schema/dimension guard")',
    '"apps/database/": ("DB", "قرارداد/validation pgvector فقط برای Operational Memory", "startup/CI", "PostgreSQL", "memory schema/dimension guard")',
)
generator = generator.replace(
    'return ("Python", "Contract/helper لایه Knowledge RAG", "RAG service", "metadata/ACL", "Runtime", "دانش رسمی governed")',
    'return ("Python", "Contract/helper لایه Cognia-only Knowledge RAG", "RAG service", "Cognia retrieval contract", "Runtime", "دانش رسمی governed فقط از Cognia")',
)
write("scripts/generate_file_index_fa.py", generator)

# Update generated code-symbol semantics if present; generator may be rerun later.
replace_all(
    "docs/CODE_SYMBOLS_FA.md",
    "دانش رسمی مثل Runbook/SOP/Architecture با embedding برای RAG.",
    "Legacy symbol removed: Governed Knowledge RAG is Cognia-only.",
)

# Repository-level architectural guard test.
guard_path = ROOT / "tests/unit/test_cognia_only_rag_architecture.py"
guard_path.write_text(
    '''from pathlib import Path\n\n\ndef test_cognia_is_the_only_rag_runtime_contract():\n    env = Path(".env.example").read_text(encoding="utf-8")\n    config = Path("domain/contracts/config.py").read_text(encoding="utf-8")\n    rag = Path("apps/rag_service/__init__.py").read_text(encoding="utf-8")\n    models = Path("domain/models.py").read_text(encoding="utf-8")\n    pgvector = Path("apps/database/pgvector_contract.py").read_text(encoding="utf-8")\n\n    assert "KNOWLEDGE_PROVIDER" not in env\n    assert "KNOWLEDGE_PROVIDER" not in config\n    assert "local_pgvector" not in rag\n    assert "KnowledgeDocument" not in models\n    assert "knowledge_documents" not in pgvector\n    assert "memory_entries" in pgvector\n    assert "CogniaClient" in rag\n\n\ndef test_historical_local_knowledge_table_is_retired_without_vector_retrieval():\n    migration = Path("database/migrations/versions/c3d4e5f6a7b8_retire_local_knowledge_rag.py").read_text(encoding="utf-8")\n    assert "legacy_knowledge_documents_archive" in migration\n    assert 'drop_column("legacy_knowledge_documents_archive", "embedding")' in migration\n''',
    encoding="utf-8",
)

# Final source scan: no runtime/provider switch or local Knowledge RAG tokens may remain.
forbidden = ("local_pgvector", "KNOWLEDGE_PROVIDER", "KnowledgeDocument")
violations: list[str] = []
for path in ROOT.rglob("*"):
    if not path.is_file() or ".git" in path.parts:
        continue
    if path == Path(__file__):
        continue
    if path.suffix.lower() not in {".py", ".md", ".yml", ".yaml", ".example", ".txt"} and path.name != ".env.example":
        continue
    try:
        text = path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        continue
    for token in forbidden:
        if token in text:
            violations.append(f"{path.relative_to(ROOT)} contains forbidden token {token}")

if violations:
    raise RuntimeError("Cognia-only RAG guard failed:\n" + "\n".join(sorted(violations)))

# knowledge_documents may exist only in historical/retirement migrations and in
# tests/CI that assert the active table is gone.
for path in ROOT.rglob("*"):
    if not path.is_file() or ".git" in path.parts:
        continue
    if path == Path(__file__):
        continue
    try:
        text = path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        continue
    if "knowledge_documents" not in text:
        continue
    rel = path.relative_to(ROOT).as_posix()
    allowed = (
        rel.startswith("database/migrations/versions/")
        or rel == ".github/workflows/quality.yml"
        or rel == "tests/unit/test_cognia_only_rag_architecture.py"
        or rel == "tests/unit/test_migration_contract.py"
    )
    if not allowed:
        raise RuntimeError(f"active/local Knowledge table reference remains in {rel}")

# Remove the one-time patch script from the product tree before commit.
Path(__file__).unlink()
print("Cognia-only RAG finalization applied successfully")
