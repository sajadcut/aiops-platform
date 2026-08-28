from apps.api import health


def test_production_readiness_requires_configured_optional_mcps(monkeypatch):
    monkeypatch.setattr(health.settings, "APP_ENV", "production")
    monkeypatch.setattr(health.settings, "KUBERNETES_MCP_URL", "https://kubernetes-mcp.internal/mcp")
    monkeypatch.setattr(health.settings, "VM_MCP_URL", "https://vm-mcp.internal/mcp")

    external = {
        "zabbix_mcp": {"healthy": True},
        "elasticsearch_mcp": {"healthy": True},
        "prometheus_mcp": {"healthy": True},
        "kubernetes_mcp": {"healthy": True},
        "vm_mcp": {"healthy": False},
    }

    assert health._external_required_ready(external) is False
    external["vm_mcp"] = {"healthy": True}
    assert health._external_required_ready(external) is True


def test_non_production_readiness_does_not_gate_on_external_mcps(monkeypatch):
    monkeypatch.setattr(health.settings, "APP_ENV", "test")
    monkeypatch.setattr(health.settings, "KUBERNETES_MCP_URL", "")
    monkeypatch.setattr(health.settings, "VM_MCP_URL", "")

    assert health._external_required_ready({}) is True
