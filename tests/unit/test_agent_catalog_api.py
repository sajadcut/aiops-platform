import asyncio
from pathlib import Path

import pytest

from apps.api.agents import AgentTelemetry, _CatalogOnlyLLMAdapter, agent_catalog, agent_metrics
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


def test_catalog_only_adapter_cannot_execute_inference():
    adapter = _CatalogOnlyLLMAdapter()

    with pytest.raises(RuntimeError, match="catalog_only_adapter_cannot_generate"):
        asyncio.run(adapter.generate("should never execute"))


def test_agent_catalog_route_has_no_operational_llm_dependency():
    source = (ROOT / "apps/api/agents.py").read_text(encoding="utf-8")

    assert "configured_llm_adapter" not in source
    assert "registry = AgentRegistry(_CatalogOnlyLLMAdapter())" in source
    assert "catalog_only_adapter_cannot_generate" in source
    assert 'Depends(require_permission("read:incident"))' in source


def test_agent_metrics_exposes_stable_dashboard_list_contract(monkeypatch):
    snapshot = {
        "application": {
            "invocations": 4,
            "successes": 3,
            "failures": 1,
            "avg_confidence": 0.625,
            "avg_evidence_coverage": 0.75,
        }
    }
    monkeypatch.setattr(AgentTelemetry, "snapshot", classmethod(lambda cls: snapshot))

    payload = asyncio.run(agent_metrics())

    assert payload["scope"] == "process_local_runtime"
    assert payload["by_agent"] == snapshot
    assert isinstance(payload["items"], list)
    assert payload["items"] == [
        {
            "agent_name": "application",
            "invocations": 4,
            "successes": 3,
            "failures": 1,
            "avg_confidence": 0.625,
            "avg_evidence_coverage": 0.75,
            "average_confidence": 0.625,
            "average_evidence_coverage": 0.75,
        }
    ]
