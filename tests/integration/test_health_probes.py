import pytest
from fastapi import Response

from apps.api.health import liveness, readiness
from domain.contracts.config import settings


@pytest.mark.asyncio
async def test_liveness_contract():
    result = await liveness()
    assert result["status"] == "alive"


@pytest.mark.asyncio
async def test_readiness_contract(monkeypatch):
    async def healthy_db():
        return {"status": "healthy", "pgvector": {"available": True}}

    async def healthy_external():
        return {
            "zabbix_mcp": {"healthy": True},
            "elasticsearch_mcp": {"healthy": True},
            "prometheus_mcp": {"healthy": True},
        }

    import apps.api.health as health
    monkeypatch.setattr(health, "_probe_database", healthy_db)
    monkeypatch.setattr(health, "_probe_external", healthy_external)
    response = Response()
    result = await readiness(response)
    assert result["status"] == "ready"
    assert response.status_code == 200


@pytest.mark.asyncio
async def test_readiness_returns_503_when_database_is_unavailable(monkeypatch):
    async def unhealthy_db():
        return {"status": "unhealthy", "error": "database_unavailable"}

    async def healthy_external():
        return {
            "zabbix_mcp": {"healthy": True},
            "elasticsearch_mcp": {"healthy": True},
            "prometheus_mcp": {"healthy": True},
        }

    import apps.api.health as health
    monkeypatch.setattr(health, "_probe_database", unhealthy_db)
    monkeypatch.setattr(health, "_probe_external", healthy_external)
    response = Response()
    result = await readiness(response)
    assert result["status"] == "not_ready"
    assert response.status_code == 503


@pytest.mark.asyncio
async def test_production_readiness_requires_external_mcp(monkeypatch):
    async def healthy_db():
        return {"status": "healthy", "pgvector": {"available": True}}

    async def degraded_external():
        return {
            "zabbix_mcp": {"healthy": True},
            "elasticsearch_mcp": {"healthy": False, "error": "dependency_unavailable"},
            "prometheus_mcp": {"healthy": True},
        }

    import apps.api.health as health
    monkeypatch.setattr(health, "_probe_database", healthy_db)
    monkeypatch.setattr(health, "_probe_external", degraded_external)
    monkeypatch.setattr(settings, "APP_ENV", "production")
    response = Response()
    result = await readiness(response)
    assert result["status"] == "not_ready"
    assert response.status_code == 503
