from apps.api import health


def test_production_readiness_requires_cognia_and_configured_optional_mcps(monkeypatch):
    monkeypatch.setattr(health.settings, "APP_ENV", "production")
    monkeypatch.setattr(health.settings, "JENKINS_MCP_URL", "https://jenkins.internal/mcp-server/mcp")
    monkeypatch.setattr(health.settings, "KUBERNETES_MCP_URL", "https://kubernetes-mcp.internal/mcp")
    monkeypatch.setattr(health.settings, "VM_MCP_URL", "https://vm-mcp.internal/mcp")

    external = {
        "cognia": {"healthy": True},
        "zabbix_mcp": {"healthy": True},
        "elasticsearch_mcp": {"healthy": True},
        "prometheus_mcp": {"healthy": True},
        "jenkins_mcp": {"healthy": True},
        "kubernetes_mcp": {"healthy": True},
        "vm_mcp": {"healthy": False},
    }

    assert health._external_required_ready(external) is False
    external["vm_mcp"] = {"healthy": True}
    assert health._external_required_ready(external) is True

    external["jenkins_mcp"] = {"healthy": False}
    assert health._external_required_ready(external) is False
    external["jenkins_mcp"] = {"healthy": True}

    external["cognia"] = {"healthy": False}
    assert health._external_required_ready(external) is False


def test_non_production_readiness_does_not_gate_on_external_dependencies(monkeypatch):
    monkeypatch.setattr(health.settings, "APP_ENV", "test")
    monkeypatch.setattr(health.settings, "JENKINS_MCP_URL", "")
    monkeypatch.setattr(health.settings, "KUBERNETES_MCP_URL", "")
    monkeypatch.setattr(health.settings, "VM_MCP_URL", "")

    assert health._external_required_ready({}) is True
