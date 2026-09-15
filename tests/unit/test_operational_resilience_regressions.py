from datetime import datetime, timezone

import pytest

from agents.shared.coordinator import IncidentCoordinator
from agents.shared.domain_agent import DomainDiagnosticAgent
from apps.api.remediation import RemediationRequest
from domain.contracts.config import settings
from integrations.zabbix.mcp_client import ZabbixMCPClient


@pytest.mark.asyncio
async def test_zabbix_problem_get_semantic_error_falls_back_to_active_view(monkeypatch):
    client = object.__new__(ZabbixMCPClient)
    calls = []

    async def call_tool(name, args):
        calls.append((name, args))
        if name == "problem_get":
            return {"isError": True, "content": [{"type": "text", "text": "API call failed"}]}
        return {"content": [{"type": "text", "text": "fallback"}]}

    def json_content(result):
        return [{
            "problems": [{
                "eventid": "100", "severity": "3", "name": "HAProxy port 8800 is down",
                "host": "NeoBanking-6.199", "time": "2026-09-15 19:00 UTC",
            }]
        }]

    monkeypatch.setattr(client, "call_tool", call_tool)
    monkeypatch.setattr(client, "json_content", json_content)
    monkeypatch.setattr(settings, "ZABBIX_MCP_SERVER_NAME", "")

    alerts = await client.get_alerts(
        since=datetime(2026, 9, 15, 18, 0, tzinfo=timezone.utc), service="haproxy"
    )

    assert [call[0] for call in calls] == ["problem_get", "problem_active_get"]
    assert len(alerts) == 1
    assert alerts[0].source_id == "100"
    assert alerts[0].service == "haproxy"


def test_focused_routing_uses_three_specialists_but_low_confidence_can_expand(monkeypatch):
    monkeypatch.setattr(settings, "AGENT_MAX_PARALLELISM", 5)
    monkeypatch.setattr(settings, "AGENT_LOW_CONFIDENCE_THRESHOLD", 0.5)
    enabled = ["vm", "infrastructure", "network", "application", "dependency"]

    focused = IncidentCoordinator.select_agents(
        {"confidence": 0.8, "handoff_agents": ["vm", "infrastructure", "network", "application"], "analysis_details": {"primary_domain": "network"}},
        enabled,
    )
    broad = IncidentCoordinator.select_agents(
        {"confidence": 0.1, "handoff_agents": [], "analysis_details": {"primary_domain": "unknown"}},
        enabled,
    )

    assert focused["selected"] == ["vm", "infrastructure", "network"]
    assert focused["routing_budget"] == 3
    assert focused["adaptive_routing"] is True
    assert len(broad["selected"]) == 5


def test_prompt_compaction_bounds_logs_processes_and_strings():
    raw = {
        "diagnostic": "service_logs",
        "entries": [f"line-{i}" for i in range(100)],
        "processes": [{"pid": i, "command": "haproxy"} for i in range(100)],
        "detail": "x" * 5000,
    }
    bounded = DomainDiagnosticAgent._bounded_prompt_value(raw)

    assert len(bounded["entries"]) == 12
    assert len(bounded["processes"]) == 12
    assert len(bounded["detail"]) < 900
    assert bounded["detail"].endswith("...[truncated]")


def test_reload_remediation_is_explicitly_supported_but_arbitrary_actions_are_rejected():
    request = RemediationRequest(target="10.100.6.199", service="haproxy", action="reload_service", target_port=8800)
    assert request.action == "reload_service"
    assert request.target_port == 8800
    with pytest.raises(Exception):
        RemediationRequest(target="10.100.6.199", service="haproxy", action="shell")
