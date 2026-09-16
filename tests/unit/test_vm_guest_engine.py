from agents.vm.engine import build_vm_guest_analysis


def metric(eid, name, value, *, timestamp="2026-09-16T10:00:00Z", **raw):
    return {"id": eid, "type": "metric", "source": "prometheus", "name": name, "value": value, "timestamp": timestamp, "raw_data": raw}


def telemetry(eid, diagnostic, **raw):
    return {"id": eid, "type": "telemetry", "source": "vm_mcp", "raw_data": {"diagnostic": diagnostic, **raw}}


def analyze(evidence):
    return build_vm_guest_analysis(
        evidence,
        service_name="haproxy",
        context={"incident_start": "2026-09-16T10:00:00Z"},
    )


def test_linux_host_uses_use_saturation_signals_not_cpu_percentage_only():
    healthy = analyze([
        metric("cpu", "cpu_utilization", 93),
        metric("cores", "cpu_cores", 8),
        metric("load", "load1", 3.5),
        metric("runq", "run_queue", 1),
        metric("psi", "psi_cpu", 0.2),
    ])
    cpu = healthy["host_analysis"]["health_matrix"]["cpu"]
    assert cpu["status"] != "saturated"

    saturated = analyze([
        metric("cpu", "cpu_utilization", 96),
        metric("cores", "cpu_cores", 4),
        metric("load", "load1", 9),
        metric("runq", "run_queue", 8),
        metric("psi", "psi_cpu", 25),
    ])
    assert saturated["host_analysis"]["health_matrix"]["cpu"]["status"] == "saturated"


def test_iowait_with_disk_latency_is_storage_causal_candidate():
    result = analyze([
        metric("iowait", "cpu_iowait", 35),
        metric("await", "disk_await", 85),
        metric("queue", "disk_queue_depth", 12),
        metric("psi-io", "psi_io", 30),
    ])
    codes = {row["code"] for row in result["causal_findings"]}
    assert "storage_pressure_visible_as_guest_cpu_wait" in codes
    assert "storage" in result["handoff_candidates"]


def test_memory_swap_and_psi_pressure_is_guest_host_pressure():
    result = analyze([
        metric("available", "memory_available_percent", 4),
        metric("swap-in", "swap_in", 500),
        metric("swap-out", "swap_out", 700),
        metric("faults", "major_page_faults", 250),
        metric("psi-mem", "psi_memory", 35),
    ])
    memory = result["host_analysis"]["health_matrix"]["memory"]
    assert memory["status"] in {"pressure", "saturated", "oom"}
    assert any(row["code"] == "guest_memory_pressure" for row in result["causal_findings"])


def test_process_snapshot_builds_parent_child_and_resource_state():
    result = analyze([
        telemetry("parent", "process_snapshot", host="vm-a", process={"pid": 100, "name": "haproxy-master"}, running=True, cpu_percent=12, memory_percent=2, fd_count=120, socket_count=30),
        telemetry("child", "process_snapshot", host="vm-a", process={"pid": 120, "ppid": 100, "name": "haproxy-worker"}, running=True, cpu_percent=44, rss_bytes=268435456, restart_count=4, fd_count=1400, socket_count=800),
    ])
    process = result["process_analysis"]
    assert process["process_count"] == 2
    assert process["parent_child_edges"][0]["evidence_ids"] == ["parent", "child"]
    child = next(row for row in process["processes"] if row["pid"] == "120")
    assert child["restart_count"] == 4
    assert child["rss_bytes"] == 268435456
    assert process["restart_behavior_candidates"]
    assert process["fd_pressure_candidates"]


def test_systemd_service_state_is_structured_without_manual_stop_inference():
    result = analyze([
        telemetry(
            "svc", "service_status", service="haproxy", os="linux", service_manager="systemd",
            load_state="loaded", active_state="inactive", sub_state="dead", result="success",
            main_pid=0, exit_status=0, restart_count=2, start_timestamp="2026-09-16T09:40:00Z",
        )
    ])
    service = result["service_analysis"]
    row = service["service_states"][0]
    assert row["load_state"] == "loaded"
    assert row["active_state"] == "inactive"
    assert row["sub_state"] == "dead"
    assert row["exit_status"] == 0
    assert "does not prove a manual stop" in service["manual_stop_policy"]
    assert result["platform_detection"]["platform"] == "linux"


def test_systemd_failed_dependencies_are_causal_and_handoff_to_dependency():
    result = analyze([
        telemetry(
            "svc", "systemd_status", service="haproxy", load_state="loaded", active_state="failed",
            sub_state="failed", result="dependency", failed_dependencies=["network-online.target", "mnt-data.mount"],
        )
    ])
    service = result["service_analysis"]
    assert service["failed_dependency_states"][0]["failed_dependencies"] == ["network-online.target", "mnt-data.mount"]
    assert any(row["code"] == "systemd_failed_dependency" for row in result["causal_findings"])
    assert "dependency" in result["handoff_candidates"]


def test_boot_and_reboot_history_correlates_with_incident_start():
    result = analyze([
        telemetry("boot", "boot_info", boot_time="2026-09-15T12:00:00Z", uptime_seconds=79200),
        {"id": "reboot", "type": "event", "source": "vm_mcp", "timestamp": "2026-09-16T09:55:00Z", "raw_data": {"diagnostic": "reboot_event", "reboot_reason": "kernel update", "boot_id": "boot-2"}},
    ])
    boot = result["boot_reboot_analysis"]
    assert boot["boot_time"] == "2026-09-15T12:00:00Z"
    assert boot["reboot_events"][0]["incident_offset_seconds"] == -300.0
    assert any(row["code"] == "reboot_near_incident" for row in result["causal_findings"])


def test_missing_layers_are_exposed_as_next_best_evidence():
    result = analyze([])
    requested = [row["evidence"] for row in result["next_best_evidence"]]
    assert any("guest host metrics" in value for value in requested)
    assert any("process snapshot" in value for value in requested)
    assert any("systemd service state" in value for value in requested)
