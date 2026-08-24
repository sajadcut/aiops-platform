import pytest

from apps.api.health import liveness, readiness


@pytest.mark.asyncio
async def test_liveness_contract():
    result = await liveness()
    assert result["status"] == "alive"


@pytest.mark.asyncio
async def test_readiness_contract(monkeypatch):
    async def healthy_db():
        return {"status": "healthy", "pgvector": {"extension_installed": True}}

    async def healthy_external():
        return {
            "zabbix": {"healthy": True},
            "elasticsearch": {"healthy": True},
            "prometheus": {"healthy": True},
        }

    import apps.api.health as health
    monkeypatch.setattr(health, "_probe_database", healthy_db)
    monkeypatch.setattr(health, "_probe_external", healthy_external)

    result = await readiness()
    assert result["status"] == "ready"
