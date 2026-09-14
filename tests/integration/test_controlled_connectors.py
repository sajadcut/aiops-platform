import pytest

from integrations.elasticsearch.client import ElasticsearchClient
from integrations.prometheus.client import PrometheusClient


@pytest.mark.asyncio
async def test_native_edge_observability_connectors_health_harness(monkeypatch):
    async def healthy(self):
        return True

    monkeypatch.setattr(ElasticsearchClient, "health_check", healthy)
    monkeypatch.setattr(PrometheusClient, "health_check", healthy)

    assert await ElasticsearchClient().health_check() is True
    assert await PrometheusClient().health_check() is True


@pytest.mark.asyncio
async def test_native_edge_observability_failure_harness(monkeypatch):
    async def failed(self):
        raise RuntimeError("controlled_connector_failure")

    monkeypatch.setattr(ElasticsearchClient, "health_check", failed)
    with pytest.raises(RuntimeError, match="controlled_connector_failure"):
        await ElasticsearchClient().health_check()
