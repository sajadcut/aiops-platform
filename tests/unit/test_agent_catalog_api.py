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


def test_durable_agent_metric_aggregation_does_not_invent_invocations():
    from apps.api.agents import _agent_metric_items

    result = _agent_metric_items(
        [{"agent_name": "vm", "incident_count": 3, "finding_count": 5,
          "average_confidence": 0.65, "latest_analysis_at": None}],
        [],
        [{"agent_name": "vm", "average_evidence_coverage": 0.7,
          "handoffs": 2, "conflicts": 1, "human_reviews": 1}],
    )
    assert result[0]["incident_count"] == 3
    assert result[0]["invocations"] is None  # historic findings are not call counts
    assert result[0]["average_confidence"] == 0.65
    assert result[0]["average_evidence_coverage"] == 0.7
    assert result[0]["handoffs"] == 2


def test_durable_agent_metric_aggregation_uses_audit_invocations():
    from apps.api.agents import _agent_metric_items

    result = _agent_metric_items(
        [{"agent_name": "application", "incident_count": 2,
          "finding_count": 2, "average_confidence": 0.6}],
        [{"agent_name": "application", "invocations": 4, "successes": 3,
          "failures": 1, "average_confidence": 0.7,
          "average_evidence_coverage": 0.8, "handoffs": 2,
          "conflicts": 1, "human_reviews": 1}],
        [],
    )
    assert result[0]["invocations"] == 4
    assert result[0]["successes"] == 3
    assert result[0]["failures"] == 1
    assert result[0]["average_evidence_coverage"] == 0.8
    assert result[0]["incident_count"] == 2


@pytest.mark.asyncio
async def test_agent_metrics_reads_all_sources_from_durable_database(monkeypatch):
    from apps.api import agents

    calls = []
    class Rows:
        def __init__(self, records):
            self.records = records

        def mappings(self):
            return self

        def all(self):
            return self.records

    class Session:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return None

        async def execute(self, query):
            sql = str(query)
            calls.append(sql)
            if "FROM findings" in sql:
                return Rows([{"agent_name": "network", "incident_count": 8,
                              "finding_count": 9, "average_confidence": 0.75}])
            if "FROM audit_events" in sql:
                return Rows([{"agent_name": "network", "invocations": 2,
                              "successes": 2, "failures": 0}])
            if "FROM workflow_checkpoints" in sql:
                return Rows([{"agent_name": "network", "average_evidence_coverage": 0.5,
                              "handoffs": 1, "conflicts": 0, "human_reviews": 0}])
            raise AssertionError(sql)

    monkeypatch.setattr(agents, "AsyncSessionLocal", Session)
    result = await agent_metrics()
    assert len(calls) == 3
    assert result["scope"] == "durable_postgresql"
    assert result["by_agent"]["network"]["incident_count"] == 8
    assert result["by_agent"]["network"]["invocations"] == 2
    assert result["by_agent"]["network"]["average_evidence_coverage"] == 0.5


@pytest.mark.asyncio
async def test_agent_metrics_fails_closed_when_database_is_unavailable(monkeypatch):
    from apps.api import agents
    from fastapi import HTTPException

    class Broken:
        async def __aenter__(self):
            raise RuntimeError("database_unavailable")

        async def __aexit__(self, *args):
            return None

    monkeypatch.setattr(agents, "AsyncSessionLocal", Broken)
    with pytest.raises(HTTPException) as error:
        await agent_metrics()
    assert error.value.status_code == 503


def test_orchestrator_persists_agent_invocations_in_audit():
    code = (ROOT / "apps/orchestrator/e2e_graph.py").read_text(encoding="utf-8")
    assert code.count('"agent_invocation_completed"') >= 3
    assert 'agent_name=name' in code
    assert 'agent_name="triage"' in code
