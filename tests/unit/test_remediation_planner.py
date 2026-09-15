from __future__ import annotations

from apps.orchestrator.runtime import DurableWorkflowRuntime
from apps.remediation_planner import RemediationPlanner
from integrations.vm.target_context import current_vm_port, current_vm_target


def _evidence(diagnostic: str, reference: str, **raw):
    return {
        "type": "telemetry",
        "source": "vm_mcp",
        "reference": reference,
        "raw_data": {"diagnostic": diagnostic, **raw},
    }


def _state(evidence, *, source="zabbix"):
    return {
        "incident_id": "incident-1",
        "evaluation": {"approved_for_decision": True},
        "context": {
            "trigger_signal": {"source": source, "summary": "service unavailable"},
            "evidence": list(evidence),
        },
        "findings": [
            {
                "agent_name": "vm",
                "recommended_actions": [
                    {
                        "action": "restart anything the model wants",
                        "read_only": False,
                        "requires_approval": True,
                        "suggested_tool": "ssh_vm",
                    }
                ],
            }
        ],
    }


def _healthy_config(target="10.100.6.199", service="haproxy.service"):
    return _evidence(
        "config_validate",
        "vm-config",
        target=target,
        service=service,
        supported=True,
        valid=True,
    )


def test_planner_builds_only_typed_request_from_live_vm_evidence():
    evidence = [
        _evidence(
            "service_status",
            "vm-service",
            target="10.100.6.199",
            service="haproxy.service",
            active_state="failed",
        ),
        _healthy_config(),
        _evidence(
            "port_listener_status",
            "vm-port",
            target="10.100.6.199",
            service="haproxy.service",
            target_port=8800,
            listening=False,
        ),
        _evidence(
            "tcp_check",
            "vm-tcp",
            target="10.100.6.199",
            service="haproxy.service",
            target_port=8800,
            reachable=False,
        ),
    ]

    result = RemediationPlanner.plan(_state(evidence))

    assert result["status"] == "planned"
    assert result["live_identity_verified"] is True
    request = result["execution_request"]
    assert request["tool_name"] == "ssh_vm"
    assert request["action"] == "restart_service"
    assert request["target"] == "10.100.6.199"
    assert request["parameters"] == {"service": "haproxy.service", "target_port": 8800}
    assert request["runbook_id"] == "vm-service-recovery"
    assert request["agent_name"] == "remediation_planner"
    assert "restart anything the model wants" not in str(request)


def test_planner_never_turns_llm_recommendation_into_write_without_live_binding():
    result = RemediationPlanner.plan(_state([]))

    assert result["status"] == "not_planned"
    assert result["reason"] == "no_live_inactive_service_evidence"
    assert result["execution_request"] is None


def test_planner_blocks_invalid_configuration():
    evidence = [
        _evidence(
            "service_status",
            "vm-service",
            target="10.100.6.199",
            service="haproxy.service",
            active_state="failed",
        ),
        _evidence(
            "config_validate",
            "vm-config",
            target="10.100.6.199",
            service="haproxy.service",
            supported=True,
            valid=False,
        ),
    ]

    result = RemediationPlanner.plan(_state(evidence))

    assert result["status"] == "not_planned"
    assert result["reason"] == "service_configuration_invalid"


def test_planner_blocks_ambiguous_live_service_bindings():
    evidence = [
        _evidence("service_status", "one", target="10.0.0.1", service="a.service", active_state="failed"),
        _evidence("service_status", "two", target="10.0.0.2", service="b.service", active_state="failed"),
        _evidence("config_validate", "config-one", target="10.0.0.1", service="a.service", supported=False, valid=None),
        _evidence("config_validate", "config-two", target="10.0.0.2", service="b.service", supported=False, valid=None),
    ]

    result = RemediationPlanner.plan(_state(evidence))

    assert result["status"] == "not_planned"
    assert result["reason"] == "ambiguous_live_service_binding"


def test_manual_trigger_is_not_eligible_for_automatic_remediation():
    evidence = [
        _evidence("service_status", "vm-service", target="10.0.0.1", service="a.service", active_state="failed"),
        _evidence("config_validate", "vm-config", target="10.0.0.1", service="a.service", supported=False, valid=None),
    ]

    result = RemediationPlanner.plan(_state(evidence, source="manual"))

    assert result["status"] == "not_planned"
    assert result["reason"] == "trigger_source_not_auto_remediation_eligible"


def test_pre_execution_revalidation_blocks_restart_after_service_self_recovers():
    request = {
        "tool_name": "ssh_vm",
        "action": "restart_service",
        "target": "10.100.6.199",
        "parameters": {"service": "haproxy.service", "target_port": 8800},
        "runbook_id": "vm-service-recovery",
    }
    fresh = [
        _evidence(
            "service_status",
            "fresh-service",
            target="10.100.6.199",
            service="haproxy.service",
            active_state="active",
        ),
        _healthy_config(),
    ]

    result = RemediationPlanner.revalidate_execution(request, fresh)

    assert result["safe_to_execute"] is False
    assert result["reason"] == "service_no_longer_unhealthy"


def test_pre_execution_revalidation_fails_closed_without_fresh_config_check():
    request = {
        "tool_name": "ssh_vm",
        "action": "restart_service",
        "target": "10.100.6.199",
        "parameters": {"service": "haproxy.service"},
        "runbook_id": "vm-service-recovery",
    }
    fresh = [
        _evidence(
            "service_status",
            "fresh-service",
            target="10.100.6.199",
            service="haproxy.service",
            active_state="failed",
        )
    ]

    result = RemediationPlanner.revalidate_execution(request, fresh)

    assert result["safe_to_execute"] is False
    assert result["reason"] == "configuration_validation_evidence_missing"


def test_durable_resume_restores_persisted_vm_target_and_port_context():
    request = {
        "tool_name": "ssh_vm",
        "target": "10.100.6.199",
        "parameters": {"service": "haproxy.service", "target_port": 8800},
    }

    tokens = DurableWorkflowRuntime._bind_execution_context(request)
    try:
        assert current_vm_target() == "10.100.6.199"
        assert current_vm_port() == 8800
    finally:
        DurableWorkflowRuntime._reset_execution_context(tokens)

    assert current_vm_target() is None
    assert current_vm_port() is None
