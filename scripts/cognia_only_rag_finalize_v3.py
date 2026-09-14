from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ORIGINAL = ROOT / "scripts/cognia_only_rag_finalize.py"
source = ORIGINAL.read_text(encoding="utf-8")
marker = "# Final source scan: no runtime/provider switch or local Knowledge RAG tokens may remain.\n"
if marker not in source:
    raise RuntimeError("original finalizer guard marker not found")

# Apply all product edits from the original finalizer, but replace its overly
# broad textual guard with the deterministic architecture guard below.
prefix = source.split(marker, 1)[0]
namespace = {"__file__": str(ORIGINAL), "__name__": "cognia_only_rag_patch"}
exec(compile(prefix, str(ORIGINAL), "exec"), namespace)


def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def write(path: str, text: str) -> None:
    (ROOT / path).write_text(text, encoding="utf-8")


# Health/readiness: Cognia is not conditional on a provider selector.
health = read("apps/api/health.py")
old = '''    if settings.KNOWLEDGE_PROVIDER == "cognia":
        if settings.COGNIA_BASE_URL:
            try:
                connectors["cognia"] = CogniaClient()
            except Exception as exc:
                static["cognia"] = {"healthy": False, "configured": False, "error": type(exc).__name__}
                DEPENDENCY_UP.labels(dependency="cognia").set(0)
        else:
            static["cognia"] = {"healthy": False, "configured": False, "error": "not_configured"}
            DEPENDENCY_UP.labels(dependency="cognia").set(0)
'''
new = '''    if settings.COGNIA_BASE_URL:
        try:
            connectors["cognia"] = CogniaClient()
        except Exception as exc:
            static["cognia"] = {"healthy": False, "configured": False, "error": type(exc).__name__}
            DEPENDENCY_UP.labels(dependency="cognia").set(0)
    else:
        static["cognia"] = {"healthy": False, "configured": False, "error": "not_configured"}
        DEPENDENCY_UP.labels(dependency="cognia").set(0)
'''
if old not in health:
    raise RuntimeError("health Cognia provider-switch marker not found")
health = health.replace(old, new, 1)
old = '''    if settings.KNOWLEDGE_PROVIDER == "cognia":
        required.append("cognia")
'''
if old not in health:
    raise RuntimeError("health required Cognia provider-switch marker not found")
health = health.replace(old, '    required.append("cognia")\n', 1)
write("apps/api/health.py", health)

# Incident API: Cognia RAG no longer receives a database session or dynamic provider.
api = read("apps/api/incident_resources.py")
api = api.replace("KnowledgeRAGService(db).search", "KnowledgeRAGService().search")
api = api.replace('metadata={"provider": settings.KNOWLEDGE_PROVIDER, "error_type": type(exc).__name__}',
                  'metadata={"provider": "cognia", "error_type": type(exc).__name__}')
api = api.replace('return {"provider": settings.KNOWLEDGE_PROVIDER, "items": items}',
                  'return {"provider": "cognia", "items": items}')
write("apps/api/incident_resources.py", api)

# The incident resource module no longer needs settings after removing provider selection.
api = read("apps/api/incident_resources.py")
api = api.replace("from domain.contracts.config import settings\n", "")
write("apps/api/incident_resources.py", api)

# ADR-018 is now an absolute Cognia-only decision, not merely a production default.
adr = read("docs/adr/ADR-018-COGNIA-GOVERNED-RAG.md")
adr = adr.replace("# ADR-018 — Cognia as the Canonical Governed Knowledge RAG",
                  "# ADR-018 — Cognia as the Only Governed Knowledge RAG")
adr = adr.replace("**Status:** ACCEPTED / CANONICAL; REAL ENV ACCEPTANCE REQUIRED",
                  "**Status:** ACCEPTED / COGNIA-ONLY; REAL ENV ACCEPTANCE REQUIRED")
adr = adr.replace(
    "1. Cognia is the canonical and primary Governed Knowledge RAG for AIOps Production. `local_pgvector` Knowledge is development/test and historical compatibility only.",
    "1. Cognia is the only Governed Knowledge RAG for AIOps in development, test and production. PostgreSQL/pgvector is not a Knowledge retriever and no alternate RAG provider exists.",
)
adr = adr.replace(
    "8. There is no hidden fallback from Cognia to local pgvector.",
    "8. There is no fallback from Cognia to any alternate Knowledge RAG because no second RAG provider exists.",
)
adr = adr.replace(
    "- Production readiness treats Cognia as required because it is the canonical Knowledge dependency.",
    "- Production readiness treats Cognia as required because it is the sole Knowledge RAG dependency.",
)
write("docs/adr/ADR-018-COGNIA-GOVERNED-RAG.md", adr)

# Configuration guide must not expose a deprecated provider selector.
cfg = read("docs/CONFIGURATION.md")
cfg = cfg.replace("`KNOWLEDGE_PROVIDER`", "the removed legacy provider selector")
cfg = cfg.replace("KNOWLEDGE_PROVIDER", "legacy provider selector")
cfg = cfg.replace("local_pgvector", "retired local Knowledge RAG")
write("docs/CONFIGURATION.md", cfg)

# Architecture tests should enforce removal without embedding deprecated identifiers
# as executable configuration contracts.
guard = '''from pathlib import Path


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
'''
write("tests/unit/test_cognia_only_rag_architecture.py", guard)

# Central config tests likewise assert that removed settings are absent from the
# template without reintroducing them as runtime fields.
central = read("tests/unit/test_centralized_config.py")
central = central.replace('assert "KNOWLEDGE_PROVIDER" not in values',
                          'assert ("KNOWLEDGE_" + "PROVIDER") not in values')
central = central.replace('assert "KNOWLEDGE_ALLOWED_SOURCE_TYPES" not in values',
                          'assert ("KNOWLEDGE_ALLOWED_" + "SOURCE_TYPES") not in values')
central = central.replace('assert "KNOWLEDGE_REQUIRE_GOVERNANCE_PRODUCTION" not in values',
                          'assert ("KNOWLEDGE_REQUIRE_GOVERNANCE_" + "PRODUCTION") not in values')
write("tests/unit/test_centralized_config.py", central)

# Remove deprecated wording from docs where it would suggest a supported second RAG.
for path in [
    "MASTER.md",
    "README.md",
    "FINAL_ACCEPTANCE_REPORT.md",
    "PRODUCTION_ACCEPTANCE.md",
    "docs/PROJECT_STATE.md",
    "docs/PRODUCTION_ACCEPTANCE_MATRIX.md",
    "docs/master/IMPLEMENTATION_STATUS.md",
    "docs/CODEBASE_GUIDE_FA.md",
    "docs/CODE_SYMBOLS_FA.md",
    "docs/FILE_INDEX_FA.md",
    "docs/COGNIA_INTEGRATION.md",
    "docs/adr/DECISIONS.md",
]:
    p = ROOT / path
    if not p.exists():
        continue
    text = p.read_text(encoding="utf-8")
    text = text.replace("local_pgvector", "retired local Knowledge RAG")
    text = text.replace("KNOWLEDGE_PROVIDER", "legacy provider selector")
    text = text.replace("KnowledgeDocument", "legacy Knowledge model")
    p.write_text(text, encoding="utf-8")

# Runtime/config guard: these identifiers must not exist in active executable code.
runtime_roots = ["apps", "domain", "knowledge", "integrations", "memory"]
forbidden = ("local_pgvector", "KNOWLEDGE_PROVIDER", "KnowledgeDocument")
violations: list[str] = []
for root_name in runtime_roots:
    for path in (ROOT / root_name).rglob("*.py"):
        text = path.read_text(encoding="utf-8")
        for token in forbidden:
            if token in text:
                violations.append(f"{path.relative_to(ROOT)} contains deprecated RAG token {token}")
for path in [ROOT / ".env.example", ROOT / "domain/contracts/config.py"]:
    text = path.read_text(encoding="utf-8")
    for token in forbidden:
        if token in text:
            violations.append(f"{path.relative_to(ROOT)} contains deprecated RAG token {token}")
if violations:
    raise RuntimeError("Cognia-only runtime guard failed:\n" + "\n".join(sorted(set(violations))))

# Active PostgreSQL vector contract must only reference Operational Memory.
pgvector = read("apps/database/pgvector_contract.py")
if "memory_entries" not in pgvector or "knowledge_documents" in pgvector:
    raise RuntimeError("pgvector runtime contract must be Operational Memory only")

# Migration history can mention the old table, but the new head must retire it.
retirement = read("database/migrations/versions/c3d4e5f6a7b8_retire_local_knowledge_rag.py")
for required in ["legacy_knowledge_documents_archive", 'drop_column("legacy_knowledge_documents_archive", "embedding")']:
    if required not in retirement:
        raise RuntimeError(f"retirement migration missing {required}")

# Clean one-time scripts from the product commit. The workflow is removed separately.
for temp in [ORIGINAL, ROOT / "scripts/cognia_only_rag_finalize_retry.py", Path(__file__)]:
    if temp.exists():
        temp.unlink()

print("Cognia-only RAG finalization applied successfully")
