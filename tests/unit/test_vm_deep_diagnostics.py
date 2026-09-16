from agents.vm.engine import build_vm_guest_analysis


def telemetry(eid, diagnostic, *, timestamp="2026-09-16T10:00:00Z", **raw):
    return {
        "id": eid,
        "type": "telemetry",
        "source": "vm_mcp",
        "timestamp": timestamp,
        "raw_data": {"diagnostic": diagnostic, **raw},
    }


def log(eid, diagnostic, message, *, timestamp="2026-09-16T10:00:00Z", **raw):
    return {
        "id": eid,
        "type": "log",
        "source": "vm_mcp",
        "timestamp": timestamp,
        "raw_data": {"diagnostic": diagnostic, "message": message, **raw},
    }


def analyze(evidence):
    return build_vm_guest_analysis(
        evidence,
        service_name="haproxy",
        context={"incident_start": "2026-09-16T10:00:00Z"},
    )


def codes(result):
    return {row["code"] for row in result["causal_findings"]}


def cause_codes(result):
    return {row["code"] for row in result["fault_classification"]["causal_candidates"]}


def test_service_inactive_is_state_not_manual_stop():
    result = analyze([
        telemetry(
            "svc", "service_status", os="linux", service_manager="systemd", service="haproxy",
            load_state="loaded", active_state="inactive", sub_state="dead",
            result="success", main_pid=0, exit_status=0,
        ),
    ])
    assert "systemd_inactive_observed" in codes(result)
    assert "manual_stop_confirmed" not in cause_codes(result)
    assert result["diagnostic_chain"][2]["stage"] == "service_active"
    assert result["diagnostic_chain"][2]["status"] == "fail"


def test_process_missing_is_observation_not_cause():
    result = analyze([
        telemetry("proc", "process_status", process={"pid": 220, "name": "haproxy"}, running=False),
    ])
    assert "process_not_running_observed" in codes(result)
    assert "process_missing_observed" in {row["code"] for row in result["fault_classification"]["observations"]}
    assert result["diagnostic_chain"][3]["status"] == "fail"


def test_process_running_but_expected_listener_missing():
    result = analyze([
        telemetry("proc", "process_status", process={"pid": 220, "name": "haproxy"}, running=True),
        telemetry("listener", "port_listener_status", listening=False, expected_port=443, port=443),
    ])
    assert "process_running_no_listener" in cause_codes(result)
    assert result["diagnostic_chain"][3]["status"] == "pass"
    assert result["diagnostic_chain"][4]["status"] == "fail"


def test_listener_local_only_is_distinct_from_remote_network_failure():
    result = analyze([
        telemetry("listener", "port_listener_status", listening=True, expected_port=443, port=443, bind_address="127.0.0.1"),
    ])
    assert result["network_analysis"]["local_only_listeners"]
    assert "listener_local_only" in cause_codes(result)
    assert "network" in result["handoff_candidates"]


def test_remote_network_failure_after_local_tcp_success():
    result = analyze([
        telemetry("listener", "port_listener_status", listening=True, port=443, bind_address="0.0.0.0"),
        telemetry("local", "tcp_check", scope="local", target="127.0.0.1", port=443, reachable=True),
        telemetry("remote", "tcp_check", scope="remote", target="10.0.10.20", port=443, reachable=False, error="timeout"),
        telemetry("route", "route_check", destination="10.0.10.0/24", reachable=False, interface="eth0"),
    ])
    assert "network_path_failure" in cause_codes(result)
    assert result["diagnostic_chain"][5]["status"] == "pass"
    assert result["diagnostic_chain"][6]["status"] == "fail"
    assert result["diagnostic_chain"][7]["status"] == "fail"
    assert "network" in result["handoff_candidates"]


def test_oom_kill_is_os_fault_with_log_chronology():
    result = analyze([
        log("oom", "kernel_log", "Out of memory: Killed process 220 (haproxy)", timestamp="2026-09-16T09:59:58Z"),
        telemetry("proc", "process_status", process={"pid": 220, "name": "haproxy"}, running=False),
    ])
    assert result["os_analysis"]["oom_events"][0]["evidence_id"] == "oom"
    assert result["log_analysis"]["chronology"][0]["evidence_id"] == "oom"
    assert "oom_kill" in cause_codes(result)
    assert result["diagnostic_chain"][1]["status"] == "fail"
    assert "infrastructure" in result["handoff_candidates"]


def test_restart_loop_remains_separate_fault_class():
    result = analyze([
        telemetry(
            "svc", "systemd_status", service="haproxy", load_state="loaded",
            active_state="activating", sub_state="auto-restart", result="exit-code",
            restart_count=7, exit_status=1,
        ),
    ])
    assert "service_restart_loop" in codes(result)
    assert "restart_loop" in cause_codes(result)
    assert "manual_stop_confirmed" not in cause_codes(result)


def test_manual_stop_requires_explicit_audit_actor_and_action():
    result = analyze([
        telemetry(
            "svc", "service_status", service="haproxy", load_state="loaded",
            active_state="inactive", sub_state="dead", result="success", exit_status=0,
        ),
        log(
            "audit", "audit_event", "service control operation",
            actor="alice", action="stop", target="haproxy",
        ),
    ])
    assert "manual_stop_confirmed" in cause_codes(result)
    action = result["fault_classification"]["confirmed_human_actions"][0]
    assert action["actor"] == "alice"
    assert action["action"] == "stop"
    assert action["evidence_id"] == "audit"


def test_stopped_word_without_actor_action_does_not_prove_manual_stop():
    result = analyze([
        telemetry(
            "svc", "service_status", service="haproxy", load_state="loaded",
            active_state="inactive", sub_state="dead", result="success", exit_status=0,
        ),
        log("journal", "journal_event", "haproxy.service stopped successfully"),
    ])
    assert "manual_stop_confirmed" not in cause_codes(result)
    assert result["fault_classification"]["confirmed_human_actions"] == []
    assert "actor+action" in result["log_analysis"]["human_action_policy"]


def test_config_error_port_conflict_dependency_and_crash_remain_separate():
    result = analyze([
        log("cfg", "service_log", "Configuration error: invalid directive"),
        log("bind", "service_log", "bind failed: Address already in use"),
        log("dep", "journal_event", "Dependency failed for HAProxy"),
        log("crash", "kernel_log", "haproxy segfault; core dumped"),
    ])
    assert {"config_error", "port_conflict", "dependency_failure", "service_crash"} <= cause_codes(result)


def test_windows_extension_normalizes_scm_and_event_log_evidence():
    result = analyze([
        telemetry(
            "scm", "windows_service_status", os="windows", service_manager="Service Control Manager",
            service="haproxy", state="running", process_id=991, start_type="auto", win32_exit_code=0,
        ),
        log(
            "evt", "windows_event_log", "Service entered the running state",
            provider="Service Control Manager", channel="System", event_id=7036, os="windows",
        ),
    ])
    assert result["platform_detection"]["platform"] == "windows"
    service = result["service_analysis"]["service_states"][0]
    assert service["manager"] == "scm"
    assert service["active_state"] == "active"
    assert result["service_analysis"]["windows_extension"]["service_manager"] == "Service Control Manager"
    assert result["log_analysis"]["chronology"][0]["event_id"] == "7036"
