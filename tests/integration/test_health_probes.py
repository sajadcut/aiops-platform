import pytest

from apps.api.health import _probe_one, liveness, readiness


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

@pytest.mark.asyncio
async def test_mcp_dependency_health_probe_forces_single_read_attempt():
    seen = []

    class FakeMCPClient:
        read_retry_attempts_override = None

        async def health_check(self):
            seen.append(self.read_retry_attempts_override)
            return False

        async def close(self):
            return None

    name, result = await _probe_one("prometheus_mcp", FakeMCPClient())

    assert name == "prometheus_mcp"
    assert result == {"healthy": False}
    assert seen == [1]

