from pathlib import Path

from apps.mcp_server.main import _TOOL_SCHEMAS, _WRITE_TOOLS


def test_provider_tool_names_match_control_plane_clients():
    assert "zabbix" not in _TOOL_SCHEMAS
    assert set(_TOOL_SCHEMAS["elasticsearch"]) == {"search_logs"}
    assert set(_TOOL_SCHEMAS["prometheus"]) == {"query_metrics", "get_prometheus_alerts"}
    assert set(_TOOL_SCHEMAS["kubernetes"]) == {"collect_kubernetes_evidence"}
    assert set(_TOOL_SCHEMAS["vm"]) == {
        "collect_vm_metrics", "host_info", "disk_status", "network_status",
        "service_status", "service_logs", "system_logs", "process_snapshot",
        "process_status", "tcp_check", "port_listener_status", "dns_check",
        "route_check", "firewall_status", "config_validate",
        "restart_service", "reload_service",
    }
    assert _WRITE_TOOLS == {"restart_service", "reload_service"}


def test_internal_mcp_server_has_no_native_zabbix_provider():
    server = Path("apps/mcp_server/main.py").read_text(encoding="utf-8")
    assert "ZabbixConnector" not in server
    assert '"zabbix": {' not in server
    assert not Path("integrations/zabbix/connector.py").exists()


def test_mcp_server_is_the_only_place_remaining_native_provider_connectors_are_composed():
    server = Path("apps/mcp_server/main.py").read_text(encoding="utf-8")
    assert "ElasticsearchClient" in server
    assert "PrometheusClient" in server
    assert "KubernetesEvidenceClient" in server
    assert "SSHVMConnector" in server

    context = Path("apps/context_service/__init__.py").read_text(encoding="utf-8")
    execution = Path("apps/api/main.py").read_text(encoding="utf-8")
    for native in ("ElasticsearchClient", "PrometheusClient", "KubernetesEvidenceClient", "SSHVMConnector"):
        assert native not in context
        assert native not in execution


def test_mcp_server_does_not_expose_arbitrary_execution_tools():
    all_tools = {tool for provider in _TOOL_SCHEMAS.values() for tool in provider}
    assert "shell" not in all_tools
    assert "execute_shell" not in all_tools
    assert "powershell" not in all_tools
    assert "execute_command" not in all_tools
