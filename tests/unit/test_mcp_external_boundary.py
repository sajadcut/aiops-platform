from pathlib import Path

import pytest

from integrations.mcp_client import MCPClient


ROOT = Path(__file__).resolve().parents[2]


def test_context_builder_uses_mcp_clients_not_native_external_connectors():
    text = (ROOT / "apps/context_service/__init__.py").read_text()
    assert "ElasticsearchMCPClient" in text
    assert "PrometheusMCPClient" in text
    assert "ZabbixMCPClient" in text
    assert "VMEdgeMCPClient" in text
    assert "from integrations.elasticsearch.client import" not in text
    assert "from integrations.prometheus.client import" not in text
    assert "from integrations.zabbix.connector import" not in text
    assert "from integrations.vm.ssh_connector import" not in text


def test_evidence_collector_has_no_native_external_fallbacks():
    text = (ROOT / "apps/context_service/evidence_collector.py").read_text()
    assert "KubernetesEvidenceClient" not in text
    assert "SSHVMConnector" not in text
    assert "ElasticsearchClient" not in text
    assert "PrometheusClient" not in text
    assert "ZabbixConnector" not in text
    assert '"source": "vm_mcp"' in text
    assert 'self.kubernetes = kubernetes' in text


def test_api_execution_registration_does_not_open_direct_ssh():
    text = (ROOT / "apps/api/main.py").read_text()
    assert "VMEdgeMCPClient" in text
    assert "SSHVMConnector" not in text
    assert "direct Control-Plane SSH is forbidden" in text


def test_mcp_client_rejects_non_allowlisted_tool():
    client = MCPClient(
        "http://mcp.test/mcp",
        "test",
        allowed_tools={"read_safe"},
        require_https=False,
    )
    with pytest.raises(PermissionError):
        import asyncio
        asyncio.run(client.call_tool("arbitrary_shell", {"command": "id"}))
    import asyncio
    asyncio.run(client.close())


def test_mcp_client_requires_https_when_configured():
    with pytest.raises(ValueError, match="mcp_https_required"):
        MCPClient("http://mcp.test/mcp", "test", allowed_tools={"read_safe"}, require_https=True)
