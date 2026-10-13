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
            "trigger_signal": {
                "source": source,
                "summary": "service unavailable",
                "raw_data": {"target_ip": "10.100.6.199"} if source == "zabbix" else {},
            },
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


def test_planner_builds_restart_for_failed_service_only_from_live_vm_evidence():
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


def test_planner_uses_start_for_inactive_dead_service():
    evidence = [
        _evidence(
            "service_status",
            "vm-service",
            target="10.100.6.199",
            service="haproxy.service",
            active_state="inactive",
            sub_state="dead",
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
    assert result["reason"] == "live_vm_service_stopped_matches_governed_start"
    assert result["execution_request"]["action"] == "start_service"
    assert result["execution_request"]["target"] == "10.100.6.199"
    assert result["execution_request"]["parameters"] == {"service": "haproxy.service", "target_port": 8800}


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


def test_pre_execution_revalidation_allows_start_only_while_service_remains_inactive():
    request = {
        "tool_name": "ssh_vm",
        "action": "start_service",
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
            active_state="inactive",
            sub_state="dead",
        ),
        _healthy_config(),
    ]

    result = RemediationPlanner.revalidate_execution(request, fresh)

    assert result["safe_to_execute"] is True
    assert result["action"] == "start_service"


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


def test_zabbix_automatic_remediation_requires_explicit_matching_target_ip():
    evidence = [
        _evidence(
            "service_status", "vm-service",
            target="10.100.6.199", service="haproxy.service", active_state="failed",
        ),
        _healthy_config(),
    ]
    state = _state(evidence)
    state["context"]["trigger_signal"]["raw_data"] = {
        "host_ip": "10.100.6.199",
        "host": "vm-01",
    }
    missing = RemediationPlanner.plan(state)
    assert missing["status"] == "not_planned"
    assert missing["reason"] == "zabbix_explicit_target_ip_required"
    assert missing["execution_request"] is None

    state["context"]["trigger_signal"]["raw_data"] = {"target_ip": "10.0.0.99"}
    mismatch = RemediationPlanner.plan(state)
    assert mismatch["status"] == "not_planned"
    assert mismatch["reason"] == "zabbix_trigger_target_mismatch"
    assert mismatch["execution_request"] is None

    state["context"]["trigger_signal"]["raw_data"] = {
        "tags": [{"tag": "target_ip", "value": "10.100.6.199"}]
    }
    matched = RemediationPlanner.plan(state)
    assert matched["status"] == "planned"
    assert matched["target"] == "10.100.6.199"


def test_non_vm_zabbix_alert_cannot_plan_vm_restart_even_with_matching_vm_evidence():
    evidence = [
        _evidence(
            "service_status", "vm-service",
            target="10.100.6.199", service="haproxy.service", active_state="failed",
        ),
        _healthy_config(),
    ]
    for platform, asset_type in [
        ("network", "network"),
        ("application", "application"),
        ("kubernetes", "kubernetes_workload"),
        ("kubernetes", "kubernetes_namespace"),
    ]:
        state = _state(evidence)
        state["context"]["trigger_signal"]["raw_data"] = {
            "platform": platform,
            "asset_type": asset_type,
            "service": "haproxy.service",
            "target_ip": "10.100.6.199",
        }
        result = RemediationPlanner.plan(state)
        assert result["status"] == "not_planned"
        assert result["reason"] == "zabbix_non_vm_signal_not_auto_remediation_eligible"
        assert result["execution_request"] is None



def test_unavailable_or_unknown_config_validator_never_authorizes_start():
    for supported, valid, success in (
        (False, None, True),
        (False, True, True),
        (True, None, True),
        (True, True, False),
    ):
        evidence = [
            _evidence("service_status", "svc", target="10.100.6.199",
                      service="haproxy.service", active_state="inactive"),
            _evidence("config_validate", "cfg", target="10.100.6.199",
                      service="haproxy.service", supported=supported,
                      valid=valid, success=success),
        ]
        valid_config, refs, reason = RemediationPlanner._configuration_precondition(
            evidence, target="10.100.6.199", service="haproxy.service"
        )
        assert valid_config is False
        assert reason != "configuration_precondition_satisfied"


def test_after_fix_newer_successful_check_replaces_older_syntax_error():
    error = _evidence("config_validate", "old-config", target="10.100.6.199",
                      service="nginx", supported=True, success=True, valid=False)
    success = _evidence("config_validate", "new-config", target="10.100.6.199",
                        service="nginx", supported=True, success=True, valid=True)
    error["timestamp"] = "2026-10-13T11:00:00Z"
    success["timestamp"] = "2026-10-13T11:06:00Z"
    allowed, refs, reason = RemediationPlanner._configuration_precondition(
        [error, success], target="10.100.6.199", service="nginx"
    )
    assert allowed is True
    assert "new-config" in refs
    assert "old-config" not in refs
    assert reason == "configuration_precondition_satisfied"
    # A later failing test must invalidate the earlier success.
    error["timestamp"] = "2026-10-13T11:08:00Z"
    allowed, _, reason = RemediationPlanner._configuration_precondition(
        [error, success], target="10.100.6.199", service="nginx"
    )
    assert allowed is False
    assert reason == "service_configuration_invalid"
    # Without ordering, disagreement must fail closed.
    error.pop("timestamp")
    success.pop("timestamp")
    allowed, _, _ = RemediationPlanner._configuration_precondition(
        [success, error], target="10.100.6.199", service="nginx"
    )
    assert allowed is False


def _dotnet_config_evidence(*, syntax_valid=True, status="syntax_valid",
                           service="gfpapi", target="10.248.16.82"):
    return [
        _evidence("config_validate", "cfg-generic", target=target, service=service,
                  supported=False, valid=None, success=True,
                  detail="config_validation_adapter_unavailable"),
        _evidence("service_runtime_discovery", "runtime", target=target,
                  service=service, success=True, runtime="dotnet",
                  entrypoint="/data/gfp/gfpapi/GFP.Endpoints.API.dll",
                  publish_directory="/data/gfp/gfpapi"),
        _evidence("dotnet_config_syntax", "json", target=target, service=service,
                  success=True, supported=True, runtime="dotnet",
                  validator="aiops-local-python-json-syntax-only",
                  validated_scope="json_syntax_only", syntax_valid=syntax_valid,
                  status=status, config_contents_exposed=False,
                  config_values_persisted=False, environment_values_read=False,
                  files=[{"file": "appsettings.json", "status":
                          "valid_json_syntax" if syntax_valid else "invalid_json_syntax"}]),
    ]


def test_dotnet_syntax_does_not_authorize_automatic_planning():
    rows = _dotnet_config_evidence()
    good, refs, reason = RemediationPlanner._configuration_precondition(
        rows, target="10.248.16.82", service="gfpapi",
    )
    assert not good and reason == "configuration_validation_unavailable"


@pytest.mark.parametrize("action,states,expected", [
    ("restart_service", "failed", True),
    ("start_service", "inactive", True),
    ("reload_service", "active", False),
])
def test_scoped_dotnet_recovery_preflight_only_for_approved_recovery(action, states, expected):
    evidence = [
        _evidence("service_status", "svc", target="10.248.16.82", service="gfpapi",
                  active_state=states),
        *_dotnet_config_evidence(),
    ]
    result = RemediationPlanner.revalidate_execution({
        "tool_name": "ssh_vm", "runbook_id": RemediationPlanner.VM_SERVICE_RUNBOOK,
        "action": action, "target": "10.248.16.82",
        "parameters": {"service": "gfpapi"},
    }, evidence)
    assert result["safe_to_execute"] is expected
    if expected:
        assert result["validation_scope"] == "dotnet_json_syntax_only"
        assert result["configuration_semantics_valid"] is None


@pytest.mark.parametrize("alter,reason", [
    ({"syntax_valid": False, "status": "invalid"},
     "dotnet_json_syntax_invalid"),
    ({"syntax_valid": None, "status": "partial"},
     "dotnet_json_syntax_validation_inconclusive"),
    ({"validator": "untrusted-checker"},
     "dotnet_json_syntax_validation_inconclusive"),
    ({"config_contents_exposed": True},
     "dotnet_json_syntax_validation_inconclusive"),
    ({"validated_scope": "unknown"},
     "dotnet_json_syntax_validation_inconclusive"),
    ({"files": []}, "dotnet_json_syntax_validation_inconclusive"),
])
def test_bad_or_partial_dotnet_validator_remains_blocked(alter, reason):
    evidence = [
        _evidence("service_status", "svc", target="10.248.16.82", service="gfpapi",
                  active_state="failed"),
        *_dotnet_config_evidence(),
    ]
    evidence[-1]["raw_data"].update(alter)
    result = RemediationPlanner.revalidate_execution({
        "tool_name": "ssh_vm", "runbook_id": RemediationPlanner.VM_SERVICE_RUNBOOK,
        "action": "restart_service", "target": "10.248.16.82",
        "parameters": {"service": "gfpapi"},
    }, evidence)
    assert not result["safe_to_execute"]
    assert result["reason"] == reason


def test_runtime_service_target_mismatch_cannot_be_used_for_dotnet_preflight():
    evidence = [
        _evidence("service_status", "svc", target="10.248.16.82",
                  service="gfpapi", active_state="failed"),
        *_dotnet_config_evidence(),
    ]
    evidence[-2]["raw_data"]["service"] = "nginx"
    result = RemediationPlanner.revalidate_execution({
        "tool_name": "ssh_vm", "runbook_id": RemediationPlanner.VM_SERVICE_RUNBOOK,
        "action": "restart_service", "target": "10.248.16.82",
        "parameters": {"service": "gfpapi"},
    }, evidence)
    assert result["safe_to_execute"] is False
    assert result["reason"] == "dotnet_runtime_identity_unverified"
