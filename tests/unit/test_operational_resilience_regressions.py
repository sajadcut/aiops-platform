from datetime import datetime, timezone

import pytest

from agents.shared.base import AgentInput
from agents.shared.coordinator import IncidentCoordinator
from agents.shared.domain_agent import DomainDiagnosticAgent
from agents.vm import VMAgent
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


class _FailingLLM:
    provider_name = "test"

    async def generate(self, *args, **kwargs):
        raise RuntimeError("synthetic_llm_failure")


@pytest.mark.asyncio
async def test_vm_deterministic_classifier_is_not_lost_when_prompt_evidence_is_capped(monkeypatch):
    monkeypatch.setattr(settings, "AGENT_MAX_EVIDENCE_ITEMS", 2)
    evidence = [
        {"reference": "noise-1", "type": "alert", "source": "zabbix", "raw_data": {"name": "noise"}},
        {"reference": "noise-2", "type": "event", "source": "zabbix", "raw_data": {"name": "noise"}},
        {"reference": "svc", "type": "telemetry", "source": "vm_mcp", "raw_data": {"diagnostic": "service_status", "service": "haproxy", "active_state": "inactive", "sub_state": "dead"}},
        {"reference": "proc", "type": "telemetry", "source": "vm_mcp", "raw_data": {"diagnostic": "process_status", "process": "haproxy", "running": False, "count": 0}},
        {"reference": "cfg", "type": "telemetry", "source": "vm_mcp", "raw_data": {"diagnostic": "config_validate", "service": "haproxy", "supported": True, "valid": True}},
        {"reference": "listen", "type": "telemetry", "source": "vm_mcp", "raw_data": {"diagnostic": "port_listener_status", "port": 8800, "supported": True, "listening": False}},
        {"reference": "tcp", "type": "telemetry", "source": "vm_mcp", "raw_data": {"diagnostic": "tcp_check", "port": 8800, "supported": True, "reachable": False}},
    ]
    output = await VMAgent(_FailingLLM()).analyze(AgentInput(
        incident_id="cap-regression",
        service_name="haproxy",
        evidence_summary="port 8800 down",
        context={"evidence": evidence},
    ))

    assert output.analysis_details["prompt_evidence_count"] == 2
    assert output.analysis_details["deterministic_evidence_count"] == len(evidence)
    assert output.analysis_details["deterministic_fault"] == "service_stopped"
    assert {"svc", "proc", "cfg", "listen", "tcp"}.issubset(set(output.evidence_ids))
    assert any(
        action.action == "start_service"
        and action.requires_approval
        and action.suggested_tool == "ssh_vm"
        for action in output.recommended_actions
    )


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


def test_deterministic_stopped_service_reaches_decision_despite_root_cause_disagreement(monkeypatch):
    monkeypatch.setattr(settings, "AGENT_MIN_EVIDENCE_COVERAGE", 0.5)
    monkeypatch.setattr(settings, "AGENT_MIN_CONSENSUS_SCORE", 0.6)
    vm = {
        "agent_name": "vm",
        "finding_type": "vm_analysis",
        "severity": "high",
        "health_status": "unhealthy",
        "confidence": 0.95,
        "evidence_ids": ["svc", "proc", "cfg", "listen", "tcp"],
        "evidence_coverage": 0.9,
        "missing_evidence": ["historical stop audit log"],
        "requires_human_review": True,
        "analysis_details": {"deterministic_fault": "service_stopped"},
        "hypotheses": [{"hypothesis": "haproxy is stopped", "probability": 0.95, "evidence_ids": ["svc", "proc", "cfg", "listen", "tcp"]}],
        "recommended_actions": [{"action": "start_service", "read_only": False, "requires_approval": True, "suggested_tool": "ssh_vm"}],
    }
    application = {
        "agent_name": "application",
        "finding_type": "application_analysis",
        "severity": "high",
        "health_status": "critical",
        "confidence": 0.8,
        "evidence_ids": ["cfg"],
        "evidence_coverage": 0.8,
        "missing_evidence": ["deployment history"],
        "requires_human_review": True,
        "hypotheses": [{"hypothesis": "configuration warning caused the outage", "probability": 0.7, "evidence_ids": ["cfg"], "conflicting_evidence_ids": ["cfg"]}],
        "recommended_actions": [],
    }
    coordination = {
        "disagreement": True,
        "contradictions": [{"agent": "application", "hypothesis": "configuration warning caused the outage", "conflicting_evidence_ids": ["cfg"]}],
        "agreement_score": 0.4,
        "requires_human_review": True,
    }

    evaluation = EvaluationGate.evaluate(
        [vm, application],
        "Current state is deterministically stopped; use governed start_service after approval and verify recovery.",
        coordination,
    )

    assert evaluation["approved_for_decision"] is True
    assert evaluation["operational_state_resolved"] is True
    assert evaluation["deterministic_recovery_agents"] == ["vm"]
    assert evaluation["blockers"] == []
    assert "unresolved_agent_disagreement" in evaluation["non_blocking_advisories"]
    assert "unresolved_evidence_conflict" in evaluation["non_blocking_advisories"]
    assert "human_review_required" in evaluation["non_blocking_advisories"]
    assert evaluation["human_review_required"] is True


def test_deterministic_recovery_does_not_bypass_unsafe_write_recommendation():
    vm = {
        "agent_name": "vm",
        "finding_type": "vm_analysis",
        "confidence": 0.95,
        "evidence_ids": ["svc", "proc", "cfg"],
        "evidence_coverage": 1.0,
        "missing_evidence": [],
        "requires_human_review": False,
        "analysis_details": {"deterministic_fault": "service_stopped"},
        "hypotheses": [],
        "recommended_actions": [
            {"action": "start_service", "read_only": False, "requires_approval": True, "suggested_tool": "ssh_vm"},
            {"action": "restart_service", "read_only": False, "requires_approval": False, "suggested_tool": "ssh_vm"},
        ],
    }
    evaluation = EvaluationGate.evaluate([vm], "governed recovery", {"agreement_score": 1.0})
    assert evaluation["approved_for_decision"] is False
    assert "unsafe_agent_recommendation" in evaluation["blockers"]


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
