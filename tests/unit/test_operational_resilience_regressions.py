from datetime import datetime, timezone

import pytest

from agents.shared.coordinator import IncidentCoordinator
from agents.shared.domain_agent import DomainDiagnosticAgent
from agents.vm.deterministic import classify_vm_service_fault
from apps.api.remediation import RemediationRequest
from apps.evaluator.gate import EvaluationGate
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

    assert len(bounded["entries"]) == 8
    assert len(bounded["processes"]) == 8
    assert len(bounded["detail"]) < 600
    assert bounded["detail"].endswith("...[truncated]")


def test_start_reload_remediation_are_supported_but_arbitrary_actions_are_rejected():
    reload_request = RemediationRequest(target="10.100.6.199", service="haproxy", action="reload_service", target_port=8800)
    start_request = RemediationRequest(target="10.100.6.199", service="haproxy", action="start_service", target_port=8800)
    assert reload_request.action == "reload_service"
    assert start_request.action == "start_service"
    assert start_request.target_port == 8800
    with pytest.raises(Exception):
        RemediationRequest(target="10.100.6.199", service="haproxy", action="shell")


def test_deterministic_vm_classifier_confirms_stopped_haproxy_from_live_evidence():
    def evidence(eid, diagnostic, **raw):
        return {
            "evidence_id": eid,
            "type": "telemetry",
            "source": "vm_mcp",
            "raw_data": {"diagnostic": diagnostic, **raw},
        }

    result = classify_vm_service_fault([
        evidence("svc", "service_status", service="haproxy", active_state="inactive", sub_state="dead"),
        evidence("proc", "process_status", process="haproxy", running=False, count=0),
        evidence("cfg", "config_validate", service="haproxy", supported=True, valid=True),
        evidence("listen", "port_listener_status", port=8800, supported=True, listening=False),
        evidence("tcp", "tcp_check", port=8800, supported=True, reachable=False),
    ], "haproxy")

    assert result is not None
    assert result["fault_code"] == "service_stopped"
    assert result["suggested_action"] == "start_service"
    assert result["confidence"] == 0.98
    assert set(result["evidence_ids"]) == {"svc", "proc", "cfg", "listen", "tcp"}


def test_partial_specialist_failure_keeps_grounded_vm_evidence_and_evaluator_can_pass(monkeypatch):
    monkeypatch.setattr(settings, "AGENT_MIN_EVIDENCE_COVERAGE", 0.5)
    monkeypatch.setattr(settings, "AGENT_MIN_CONSENSUS_SCORE", 0.5)
    grounded = {
        "agent_name": "vm",
        "finding_type": "vm_analysis",
        "severity": "medium",
        "health_status": "unhealthy",
        "confidence": 0.95,
        "evidence_ids": ["svc", "proc", "cfg", "listen", "tcp"],
        "evidence_coverage": 1.0,
        "missing_evidence": [],
        "requires_human_review": False,
        "hypotheses": [{"hypothesis": "haproxy is stopped", "probability": 0.95, "evidence_ids": ["svc", "proc", "cfg"]}],
        "recommended_actions": [{"action": "start_service", "read_only": False, "requires_approval": True}],
    }
    failed = {
        "agent_name": "application",
        "finding_type": "application_error",
        "severity": "unknown",
        "health_status": "unknown",
        "confidence": 0.0,
        "evidence_ids": [],
        "evidence_coverage": 0.0,
        "missing_evidence": ["successful specialist analysis"],
        "requires_human_review": True,
    }

    coordination = IncidentCoordinator.synthesize([grounded, failed])
    assert coordination["evidence_count"] == 5
    assert coordination["grounded_agents"] == ["vm"]
    assert coordination["failed_agents"] == ["application"]
    assert coordination["degraded_specialist_analysis"] is True
    assert coordination["requires_human_review"] is False

    evaluation = EvaluationGate.evaluate([grounded, failed], "Start HAProxy only after approval, then verify port 8800.", coordination)
    assert evaluation["approved_for_decision"] is True
    assert evaluation["specialist_failures"] == ["application"]
    assert evaluation["degraded_specialist_analysis"] is True
    assert "specialist_failure" not in evaluation["blockers"]


def test_total_specialist_failure_still_fails_closed():
    failed = {
        "agent_name": "vm",
        "finding_type": "vm_error",
        "confidence": 0.0,
        "evidence_ids": [],
        "evidence_coverage": 0.0,
        "missing_evidence": ["successful specialist analysis"],
        "requires_human_review": True,
    }
    coordination = IncidentCoordinator.synthesize([failed])
    evaluation = EvaluationGate.evaluate([failed], "Manual investigation required.", coordination)
    assert evaluation["approved_for_decision"] is False
    assert "specialist_failure" in evaluation["blockers"]
