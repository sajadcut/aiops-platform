from pathlib import Path

from apps.mcp_server.main import _TOOL_SCHEMAS


def test_provider_tool_names_match_control_plane_clients():
    assert set(_TOOL_SCHEMAS["zabbix"]) == {"get_zabbix_alerts"}
    assert set(_TOOL_SCHEMAS["elasticsearch"]) == {"search_logs"}
    assert set(_TOOL_SCHEMAS["prometheus"]) == {"query_metrics", "get_prometheus_alerts"}
    assert set(_TOOL_SCHEMAS["kubernetes"]) == {"collect_kubernetes_evidence"}
    assert set(_TOOL_SCHEMAS["vm"]) == {"collect_vm_metrics", "service_status", "process_snapshot", "restart_service"}


def test_mcp_server_is_the_only_place_native_provider_connectors_are_composed():
    server = Path("apps/mcp_server/main.py").read_text(encoding="utf-8")
    assert "ElasticsearchClient" in server
    assert "PrometheusClient" in server
    assert "ZabbixConnector" in server
    assert "KubernetesEvidenceClient" in server
    assert "SSHVMConnector" in server

    context = Path("apps/context_service/__init__.py").read_text(encoding="utf-8")
    execution = Path("apps/api/main.py").read_text(encoding="utf-8")
    for native in ("ElasticsearchClient", "PrometheusClient", "ZabbixConnector", "KubernetesEvidenceClient", "SSHVMConnector"):
        assert native not in context
        assert native not in execution


def test_mcp_server_does_not_expose_arbitrary_execution_tools():
    all_tools = {tool for provider in _TOOL_SCHEMAS.values() for tool in provider}
    assert "shell" not in all_tools
    assert "execute_shell" not in all_tools
    assert "powershell" not in all_tools
    assert "execute_command" not in all_tools
