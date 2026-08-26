from pathlib import Path

from domain.contracts.config import settings

ROOT = Path(__file__).resolve().parents[2]


def test_prometheus_adapter_uses_upstream_tool_names():
    text = (ROOT / "integrations/prometheus/mcp_client.py").read_text(encoding="utf-8")
    assert '"range_query"' in text
    assert '"list_alerts"' in text
    assert '"query_metrics"' not in text
    assert '"get_prometheus_alerts"' not in text


def test_elastic_adapter_uses_agent_builder_only():
    text = (ROOT / "integrations/elasticsearch/mcp_client.py").read_text(encoding="utf-8")
    assert '"platform.core.execute_esql"' in text
    assert "ELASTIC_AGENT_BUILDER_INDEX_PATTERN" in text
    assert "ELASTIC_AGENT_BUILDER_MCP_NAMESPACES" in text
    assert "query_body" not in text
    assert 'call_tool("search"' not in text
    assert '"list_indices"' not in text
    assert "mcp-server-elasticsearch" in text


def test_elastic_agent_builder_config_is_canonical():
    env = (ROOT / ".env").read_text(encoding="utf-8")
    assert "ELASTIC_STACK_VERSION=9.3.2" in env
    assert "ELASTICSEARCH_MCP_URL=http://localhost:5601/api/agent_builder/mcp" in env
    assert 'ELASTIC_AGENT_BUILDER_MCP_NAMESPACES=["platform.core"]' in env
    assert "ELASTIC_AGENT_BUILDER_INDEX_PATTERN=logs-*" in env
    assert "ELASTICSEARCH_MCP_INDEX_PATTERN" not in env
    assert "elastic/mcp-server-elasticsearch" not in env


def test_elastic_agent_builder_minimum_version_contract():
    version = tuple(int(part) for part in settings.ELASTIC_STACK_VERSION.split(".")[:2])
    assert version >= (9, 2)
    assert "/api/agent_builder/mcp" in settings.ELASTICSEARCH_MCP_URL
    assert "platform.core" in settings.ELASTIC_AGENT_BUILDER_MCP_NAMESPACES


def test_zabbix_adapter_uses_read_only_initmax_tools():
    text = (ROOT / "integrations/zabbix/mcp_client.py").read_text(encoding="utf-8")
    assert '"problem_get"' in text
    assert '"problem_active_get"' in text
    assert 'zabbix_raw_api_call' not in text
    assert 'action_confirm' not in text


def test_mcp_client_supports_standard_streamable_http_lifecycle():
    text = (ROOT / "integrations/mcp_client.py").read_text(encoding="utf-8")
    assert '"initialize"' in text
    assert '"notifications/initialized"' in text
    assert '"Mcp-Session-Id"' in text
    assert '"text/event-stream"' in text


def test_upstream_provider_settings_are_explicit():
    text = (ROOT / ".env").read_text(encoding="utf-8")
    assert "ZABBIX_MCP_SERVER_NAME=" in text
    assert "ELASTIC_AGENT_BUILDER_MCP_NAMESPACES=" in text
    assert "PROMETHEUS_MCP_SERVICE_LABEL=" in text
    assert "MCP_PROTOCOL_VERSION=2025-03-26" in text
