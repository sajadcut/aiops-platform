import asyncio
from pathlib import Path

from apps.api.agents import agent_catalog
from domain.contracts.config import settings


ROOT = Path(__file__).resolve().parents[2]


def test_agent_catalog_does_not_require_llm_runtime_configuration(monkeypatch):
    """Dashboard metadata must stay readable when the execution LLM is unavailable."""
    monkeypatch.setattr(settings, "APP_ENV", "production")
    monkeypatch.setattr(settings, "LLM_PROVIDER", "mock")
    monkeypatch.setattr(settings, "AGENT_ENABLED_AGENTS", ["application", "database"])

    payload = asyncio.run(agent_catalog())

    assert payload["catalog_status"] == "ready"
    assert payload["execution_boundary"] == "agents_are_analysis_only"
    assert payload["enabled"] == ["application", "database"]
    assert "application" in payload["known"]
    assert "database" in payload["known"]
    manifests = {item["name"]: item for item in payload["items"]}
    assert manifests["application"]["enabled"] is True
    assert manifests["database"]["enabled"] is True
    assert manifests["application"]["production_status"] == "analysis_only"


def test_agent_catalog_route_has_no_llm_adapter_dependency():
    source = (ROOT / "apps/api/agents.py").read_text(encoding="utf-8")

    assert "configured_llm_adapter" not in source
    assert "registry = AgentRegistry()" in source
    assert 'Depends(require_permission("read:incident"))' in source
