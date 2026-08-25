import pytest

from domain.contracts.config import settings
from knowledge import EmbeddingService
from apps.orchestrator.e2e_graph import E2EOrchestrator


@pytest.mark.asyncio
async def test_deterministic_embedding_is_forbidden_in_production(monkeypatch):
    monkeypatch.setattr(settings, "APP_ENV", "production")
    monkeypatch.setattr(settings, "EMBEDDING_PROVIDER", "deterministic")
    with pytest.raises(RuntimeError, match="deterministic_embedding_provider_forbidden_in_production"):
        await EmbeddingService.generate_embedding("incident")


def test_production_orchestrator_requires_explicit_llm_adapter(monkeypatch):
    monkeypatch.setattr(settings, "APP_ENV", "production")
    with pytest.raises(RuntimeError, match="production_llm_adapter_required"):
        E2EOrchestrator()
