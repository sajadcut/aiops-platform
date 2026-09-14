from pathlib import Path

import pytest

from integrations.mcp_client import MCPClient


ROOT = Path(__file__).resolve().parents[2]
_NATIVE_MARKERS = (
    "from integrations.elasticsearch.client import ElasticsearchClient",
    "from integrations.prometheus.client import PrometheusClient",
    "from integrations.zabbix.connector import ZabbixConnector",
    "from integrations.kubernetes.client import KubernetesEvidenceClient",
    "from integrations.vm.ssh_connector import SSHVMConnector",
)


def test_context_builder_uses_mcp_clients_not_native_external_connectors():
    text = (ROOT / "apps/context_service/__init__.py").read_text()
    assert "ElasticsearchMCPClient" in text
    assert "PrometheusMCPClient" in text
    assert "ZabbixMCPClient" in text
    assert "VMEdgeMCPClient" in text
    for marker in _NATIVE_MARKERS:
        assert marker not in text


def test_zabbix_is_mcp_only_and_has_no_direct_runtime_config():
    assert not (ROOT / "integrations/zabbix/connector.py").exists()
    config = (ROOT / "domain/contracts/config.py").read_text(encoding="utf-8")
    template = (ROOT / ".env.example").read_text(encoding="utf-8")
    server = (ROOT / "apps/mcp_server/main.py").read_text(encoding="utf-8")
    for obsolete in ("ZABBIX_URL", "ZABBIX_USERNAME", "ZABBIX_PASSWORD", "ZABBIX_TIMEOUT_SECONDS"):
        assert obsolete not in config
        assert obsolete not in template
    assert "ZABBIX_MCP_URL" in config
    assert "ZABBIX_MCP_AUTH_HEADER" in config
    assert "ZabbixMCPClient" not in server
    assert "ZabbixConnector" not in server
    assert '"zabbix": {' not in server


def test_evidence_collector_has_no_native_external_fallbacks():
    text = (ROOT / "apps/context_service/evidence_collector.py").read_text()
    for native in ("KubernetesEvidenceClient", "SSHVMConnector", "ElasticsearchClient", "PrometheusClient", "ZabbixConnector"):
        assert native not in text
    assert '"source": "vm_mcp"' in text
    assert 'self.kubernetes = kubernetes' in text


def test_control_plane_apps_cannot_import_native_operational_connectors():
    violations = []
    for path in (ROOT / "apps").rglob("*.py"):
        if "mcp_server" in path.parts:
            continue
        text = path.read_text(encoding="utf-8")
        for marker in _NATIVE_MARKERS:
            if marker in text:
                violations.append(f"{path.relative_to(ROOT)}:{marker}")
    assert not violations, "native external connector bypasses found: " + ", ".join(violations)


def test_orchestrator_and_health_use_mcp_providers():
    orchestrator = (ROOT / "apps/orchestrator/e2e_graph.py").read_text(encoding="utf-8")
    health = (ROOT / "apps/api/health.py").read_text(encoding="utf-8")
    for text in (orchestrator, health):
        assert "ElasticsearchMCPClient" in text
        assert "PrometheusMCPClient" in text
        assert "ZabbixMCPClient" in text
    for marker in _NATIVE_MARKERS:
        assert marker not in orchestrator
        assert marker not in health


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
    )
    with pytest.raises(PermissionError):
        import asyncio
        asyncio.run(client.call_tool("arbitrary_shell", {"command": "id"}))
    import asyncio
    asyncio.run(client.close())


def test_mcp_client_supports_http_and_https():
    import asyncio
    http_client = MCPClient("http://mcp.test/mcp", "test-http", allowed_tools={"read_safe"})
    https_client = MCPClient("https://mcp.test/mcp", "test-https", allowed_tools={"read_safe"})
    asyncio.run(http_client.close())
    asyncio.run(https_client.close())
