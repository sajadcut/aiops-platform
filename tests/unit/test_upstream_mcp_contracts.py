from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def test_prometheus_adapter_uses_upstream_tool_names():
    text = (ROOT / "integrations/prometheus/mcp_client.py").read_text(encoding="utf-8")
    assert '"range_query"' in text
    assert '"list_alerts"' in text
    assert '"query_metrics"' not in text
    assert '"get_prometheus_alerts"' not in text


def test_elasticsearch_adapter_uses_upstream_search_contract():
    text = (ROOT / "integrations/elasticsearch/mcp_client.py").read_text(encoding="utf-8")
    assert '"search"' in text
    assert '"query_body"' in text
    assert '"index"' in text
    assert '"search_logs"' not in text


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
    text = (ROOT / ".env.example").read_text(encoding="utf-8")
    assert "ZABBIX_MCP_SERVER_NAME=" in text
    assert "ELASTICSEARCH_MCP_INDEX_PATTERN=" in text
    assert "PROMETHEUS_MCP_SERVICE_LABEL=" in text
    assert "MCP_PROTOCOL_VERSION=2025-03-26" in text
