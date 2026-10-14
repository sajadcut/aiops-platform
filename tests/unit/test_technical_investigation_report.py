"""Regression tests for the durable, non-executing technical incident report."""
from datetime import datetime, timedelta, timezone

import pytest

from apps.technical_investigation_report import build_technical_investigation
from apps.context_service.evidence_collector import EvidenceCollector
from integrations.vm.target_context import bind_vm_target, reset_vm_target

NOW = datetime(2026, 10, 14, 10, 0, tzinfo=timezone.utc)
HOST = "10.248.16.82"
SERVICE = "gfpapi"


def vm(diagnostic, values=None, *, minutes=0, host=HOST, service=SERVICE, ref=None):
    return {
        "id": ref or ("ev-" + diagnostic), "source": "vm_mcp",
        "created_at": (NOW - timedelta(minutes=minutes)).isoformat(),
        "raw_data": {"target": host, "service": service, "diagnostic": diagnostic,
                     "success": True, **(values or {})},
    }


def provider(source, status="queried", count=0, *, minutes=0):
    return {
        "id": "ev-" + source, "source": source,
        "created_at": (NOW - timedelta(minutes=minutes)).isoformat(),
        "raw_data": {"status": status, "result_count": count, "service": SERVICE},
    }


def report(*rows, incident=None, knowledge=None):
    return build_technical_investigation(
        incident=incident or {"service": SERVICE, "started_at": NOW.isoformat(),
                              "context": {"trigger_signal": {"payload": {"target_ip": HOST}}}},
        evidence=list(rows),
        knowledge=knowledge or {"status": "empty", "accepted_count": 0, "rejected_count": 1},
        now=NOW,
        approval={"status": "not_recorded"},
    )


def domain(report, name):
    return next(x for x in report["domains"] if x["key"] == name)


def test_gfpapi_systemd_timeout_is_confirmed_symptom_not_root_cause():
    r = report(vm("service_status", {
        "active_state": "failed", "sub_state": "failed", "result": "timeout",
        "main_pid": 0, "restart_count": 0, "timeout_start_usec": "90s",
    }))
    systemd = domain(r, "systemd")
    assert systemd["status"] == "investigated"
    assert "Result=timeout" in systemd["technical_result"]
    assert systemd["evidence"][0]["id"] == "ev-service_status"
    assert r["rca"]["confirmed_facts"][0]["evidence_refs"] == ["ev-service_status"]
    assert r["rca"]["cause_confirmed"] is False
    assert r["rca"]["likely_hypotheses"][0]["confidence"] is None
    assert r["actions"]["conditional"][0]["approval_required"] is True
    assert r["read_only"] is True


def test_dotnet_syntax_valid_does_not_hide_unsupported_generic_validator():
    r = report(
        vm("config_validate", {"supported": False, "valid": None}),
        vm("dotnet_config_syntax", {"supported": True, "syntax_valid": True,
            "files": [{"file": "appsettings.json", "status": "valid_json_syntax"},
                      {"file": "runtimeconfig.json", "status": "valid_json_syntax"}]}),
    )
    result = domain(r, "config")["technical_result"]
    assert "Unsupported" in result
    assert "JSON Syntax: Valid" in result
    assert "Runtime Healthy" in result
    assert len(domain(r, "config")["evidence"]) == 2


@pytest.mark.parametrize(("status", "expected"), [
    ("queried", "queried_zero_results"),
    ("unavailable", "query_failed"),
    ("error", "query_failed"),
    ("skipped", "not_applicable"),
])
def test_elastic_provider_states_are_not_equated_with_health(status, expected):
    r = report(provider("elasticsearch", status))
    elastic = domain(r, "elastic")
    assert elastic["status"] == expected
    assert "Match=0" in elastic["technical_result"] if status == "queried" else True
    assert r["rca"]["cause_confirmed"] is False


def test_elastic_query_with_results_includes_counts_not_fabricated_failure():
    rows = [
        provider("elasticsearch", count=2),
        {"id": "log1", "source": "elasticsearch", "created_at": NOW.isoformat(),
         "raw_data": {"service": SERVICE, "level": "error", "message": "startup problem"}},
        {"id": "log2", "source": "elasticsearch", "created_at": NOW.isoformat(),
         "raw_data": {"service": SERVICE, "severity": "warning", "message": "retry"}},
    ]
    r = report(*rows)
    assert domain(r, "elastic")["status"] == "queried_with_results"
    assert "Error=1" in domain(r, "elastic")["technical_result"]
    assert "Warning=1" in domain(r, "elastic")["technical_result"]
    assert "startup problem" not in str(r)  # arbitrary raw log text never displayed


def test_journal_signatures_and_missing_journal_are_distinguished():
    absent = report(vm("service_status", {"active_state": "failed"}))
    assert domain(absent, "journal")["status"] == "not_queried"
    assert domain(absent, "journal")["missing_reason"]
    present = report(vm("service_logs", {"entries": [
        "startup: timed out waiting for dependency", "Killed process due to out of memory",
        "unrelated line",
    ]}))
    facts = domain(present, "journal")["evidence"][0]["facts"]
    assert facts["journal_lines"] == 3
    assert facts["oom_mentions"] == 1
    assert facts["timeout_mentions"] == 1
    assert "Killed process" not in str(present)


def test_disk_pressure_and_large_logs_do_not_create_unproven_causality():
    r = report(vm("disk_status", {"filesystems": [
        {"mount": "/var", "use_percent": "98%", "available": "123"},
    ], "inodes": []}),
    vm("disk_forensics", {"large_files": [{"path": "/var/log/daemon.log", "size_bytes": 123456}]}))
    assert "98%" in domain(r, "disk")["technical_result"]
    assert "/var/log/daemon.log" in str(domain(r, "disk")["evidence"])
    assert r["rca"]["cause_confirmed"] is False
    assert "حذف" in " ".join(r["actions"]["prohibited"])


def test_memory_without_process_culprit_remains_snapshot_only():
    r = report(vm("memory_diagnostics", {
        "total_mb": 8192, "available_mb": 128, "used_percent": 98.4,
        "swap_used_mb": 10, "psi_memory_some_avg10": 2.7,
        "top_processes": [{"pid": 144, "command": "dotnet", "rss_mb": 700}],
    }))
    result = domain(r, "resources")["technical_result"]
    assert "98.4%" in result
    assert "PSI avg10=2.7" in result
    assert "علت Timeout را اثبات نمی‌کند" in result


def test_dotnet_process_name_false_negative_is_not_reported_as_confirmed_absence():
    r = report(vm("service_status", {"active_state": "failed", "main_pid": 0}),
               vm("process_status", {"running": False, "count": 0}))
    assert "MainPID" in domain(r, "network")["technical_result"]
    assert "dotnet" in domain(r, "network")["technical_result"]
    assert not any("process" in x["text"].lower() for x in r["rca"]["confirmed_facts"])


def test_other_host_other_service_and_stale_evidence_are_not_live():
    r = report(vm("service_status", {"active_state": "active"}, host="10.9.9.9"),
               vm("service_status", {"active_state": "active"}, service="nginx"),
               vm("service_status", {"active_state": "failed"}, minutes=30))
    assert r["identity_mismatch_count"] == 2
    assert domain(r, "systemd")["status"] == "stale"
    assert domain(r, "systemd")["missing_reason"]


def test_no_cognia_nginx_material_is_injected_for_dotnet_service():
    r = report(knowledge={"status": "filtered_empty", "accepted_count": 0, "rejected_count": 3})
    assert domain(r, "cognia")["status"] == "queried_zero_results"
    assert "اسناد مرتبط: 0" in domain(r, "cognia")["technical_result"]
    assert "nginx" not in str(r)


def test_recovery_or_approval_cannot_be_inferred_from_report():
    r = report(provider("zabbix", "queried", 0), vm("service_status", {"active_state": "active"}))
    assert r["actions"]["conditional"][0]["status"] == "proposed_not_executed"
    assert r["actions"]["conditional"][0]["approval_required"] is True
    assert r["approval_status"] == "not_recorded"
    assert len(r["actions"]["read_only"]) <= 5


@pytest.mark.asyncio
async def test_failed_service_triggers_bounded_read_only_vm_drilldown():
    class VM:
        def __init__(self):
            self.calls = []
        async def service_status(self, host, name):
            self.calls.append("service_status")
            return {"success": True, "active_state": "failed", "result": "timeout"}
        async def service_logs(self, host, name):
            self.calls.append("service_logs")
            return {"success": True, "logs": ["startup timeout"]}
        async def service_runtime_discovery(self, host, name):
            self.calls.append("service_runtime_discovery")
            return {"success": True, "runtime": "dotnet"}
        async def dotnet_config_syntax(self, host, name):
            self.calls.append("dotnet_config_syntax")
            return {"success": True, "supported": True, "syntax_valid": True}
        async def system_logs(self, host):
            self.calls.append("system_logs")
            return {"success": True, "logs": ["system log"]}
        async def memory_diagnostics(self, host):
            self.calls.append("memory_diagnostics")
            return {"success": True, "available_mb": 512}
        async def process_snapshot(self, host):
            self.calls.append("process_snapshot")
            return {"success": True, "processes": []}
        async def config_validate(self, host, name):
            self.calls.append("config_validate")
            return {"success": True, "supported": False, "valid": None}
    vm_client = VM()
    t = bind_vm_target(HOST)
    try:
        result = await EvidenceCollector(vm=vm_client).collect(SERVICE, NOW)
    finally:
        reset_vm_target(t)
    for name in ("service_status", "service_logs", "system_logs",
                 "memory_diagnostics", "process_snapshot", "service_runtime_discovery",
                 "dotnet_config_syntax"):
        assert name in vm_client.calls
    assert all(call not in vm_client.calls for call in ("restart_service", "delete_logs", "kill_process"))
    assert any(row["raw_data"].get("diagnostic") == "dotnet_config_syntax"
               for row in result["evidence"])


def test_conflicting_zabbix_problem_and_fresh_running_systemd_is_visible():
    zabbix = {
        "id": "zbx-problem", "type": "alert", "source": "zabbix",
        "created_at": NOW.isoformat(),
        "raw_data": {"service": SERVICE, "status": "problem"},
    }
    r = report(zabbix, vm("service_status", {"active_state": "active", "sub_state": "running"}))
    assert len(r["conflicts"]) == 1
    assert {"zbx-problem", "ev-service_status"} <= set(r["conflicts"][0]["evidence_refs"])
    assert r["rca"]["cause_confirmed"] is False


def test_normal_disk_use_does_not_create_pressure_hypothesis():
    r = report(vm("disk_status", {
        "filesystems": [{"mount": "/var", "use_percent": "22%", "available": "123456"}],
        "inodes": [],
    }))
    assert not any("Disk" in h["title"] for h in r["rca"]["likely_hypotheses"])


def test_stale_failed_systemd_is_historical_not_current_confirmed_fact():
    r = report(vm("service_status", {
        "active_state": "failed", "result": "timeout",
    }, minutes=120))
    assert domain(r, "systemd")["status"] == "stale"
    assert r["rca"]["confirmed_facts"] == []
    assert r["rca"]["cause_confirmed"] is False



def test_real_vm_collector_metric_shape_is_visible_and_attributed():
    """Do not expect one raw_data.metrics dictionary from the EvidenceCollector."""
    rows = [
        vm("collect_vm_metrics", {"name": "cpu_usage", "value": 44.5}, ref="cpu-obs"),
        vm("collect_vm_metrics", {"name": "memory_usage", "value": 92.7}, ref="mem-obs"),
        vm("collect_vm_metrics", {"name": "swap_usage", "value": 81.0}, ref="swap-obs"),
        vm("collect_vm_metrics", {"name": "io_wait", "value": 12.3}, ref="io-obs"),
    ]
    result = domain(report(*rows), "resources")
    assert "CPU=44.5%" in result["technical_result"]
    assert "RAM Used=92.7%" in result["technical_result"]
    assert "Swap Usage=81%" in result["technical_result"]
    assert "IO Wait=12.3%" in result["technical_result"]
    assert "MemAvailable=ثبت نشده" in result["technical_result"]
    assert {row["id"] for row in result["evidence"]} == {
        "cpu-obs", "mem-obs", "swap-obs", "io-obs"
    }


def test_failed_or_unavailable_elastic_cannot_claim_query_success():
    failed = report(provider("elasticsearch", "error", 0))
    for word in ("هیچ Query موفقی", "error"):
        assert word in domain(failed, "elastic")["technical_result"]
    assert "Query اجراشده=1" not in domain(failed, "elastic")["technical_result"]
    unavailable = report(provider("elasticsearch", "unavailable", 0))
    assert "هیچ Query موفقی" in domain(unavailable, "elastic")["technical_result"]
    assert "Match=0" not in domain(unavailable, "elastic")["technical_result"]


def test_elastic_success_is_not_host_attributed_if_provider_only_filtered_service():
    row = provider("elasticsearch", "queried", 3)
    row["raw_data"].update({
        "query_service": "gfpapi", "query_since": "2026-10-14T09:50:00Z",
        "query_until": "2026-10-14T10:00:00Z", "host_filter_applied": False,
    })
    report_row = domain(report(row), "elastic")
    assert report_row["status"] == "queried_with_results"
    assert "Match=3" in report_row["technical_result"]
    assert "انتساب خطا به این VM مستقلاً تأیید نشده" in report_row["technical_result"]
    assert report_row["evidence"][0]["id"] == "ev-elasticsearch"


def test_actual_nested_disk_forensics_surfaces_top_file_sizes_and_growth_limits():
    disk = vm("disk_status", {
        "filesystems": [{"mount": "/var/log", "use_percent": "100%",
                          "available": "0"}], "inodes": []
    })
    forensic = vm("disk_forensics", {
        "mounts": [{"mount": "/var/log", "used_percent": 100,
                    "files": [{"path": "/var/log/syslog.1", "size_bytes": 3_024_000_000,
                               "growth_measured": True, "growth_confirmed": False},
                              {"path": "/var/log/daemon.log.1", "size_bytes": 3_000_000_000,
                               "growth_measured": False}]}]
    })
    result = report(disk, forensic)
    disk_summary = domain(result, "disk")["technical_result"]
    assert "/var/log: used=100%" in disk_summary
    assert "/var/log/syslog.1" in disk_summary
    assert "رشد مشاهده نشد" in disk_summary
    assert "رشد سنجیده نشد" in disk_summary
    assert "حذف فایل مجاز نیست" in disk_summary
    assert result["rca"]["cause_confirmed"] is False


def test_journal_signature_counts_do_not_expose_raw_sensitive_lines():
    rows = [
        vm("service_logs", {"entries": [
            "Token=internalSecret timed out while starting gfpapi",
            "Permission denied while opening socket",
        ]}),
        vm("system_logs", {"entries": [
            "Kernel: oom-kill invoked", "Unhandled exception in module",
        ]}),
    ]
    summary = domain(report(*rows), "journal")["technical_result"]
    assert "Journal lines=4" in summary
    assert "Timeout=1" in summary
    assert "OOM=1" in summary
    assert "Exception=1" in summary
    assert "Permission=1" in summary
    assert "internalSecret" not in str(report(*rows))


def test_network_section_requires_pid_and_listener_correlation():
    r = report(
        vm("service_status", {"active_state": "active", "sub_state": "running",
                              "main_pid": 420}),
        vm("service_runtime_discovery", {"runtime": "dotnet",
                                          "entrypoint": "/data/gfp/gfpapi/GFP.Endpoints.API.dll"}),
        vm("process_status", {"running": False, "count": 0}),
        vm("port_listener_status", {"listening": True, "port": 8080}),
        vm("tcp_check", {"reachable": False, "port": 8080}),
    )
    net = domain(r, "network")["technical_result"]
    assert "MainPID=420" in net
    assert "Listener=True" in net
    assert "TCP reachable=False" in net
    assert "dotnet" in net
    assert r["rca"]["cause_confirmed"] is False
    assert not any("process" in x["text"].lower() for x in r["rca"]["confirmed_facts"])


def test_disk_forensics_reports_file_sizes_without_contents_or_delete_claims():
    r = report(vm("disk_forensics", {
        "mounts": [{"mount": "/var/log", "used_percent": 100, "files": [
            {"path": "/var/log/syslog.1", "size_bytes": 3023907803, "owner_service": None},
            {"path": "/var/log/daemon.log.1", "size_bytes": 3022947143},
            {"path": "/etc/shadow", "size_bytes": 9000},
            {"path": "/var/log/app.log", "size_bytes": 8, "content": "TOP_SECRET"},
        ]}],
        "content_inspected": False,
        "delete_authorized": False,
    }))
    disk = domain(r, "disk")
    facts = disk["evidence"][0]["facts"]
    assert facts["largest_log_files"] == [
        {"path": "/var/log/syslog.1", "size_bytes": 3023907803},
        {"path": "/var/log/daemon.log.1", "size_bytes": 3022947143},
        {"path": "/var/log/app.log", "size_bytes": 8},
    ]
    assert "/etc/shadow" not in str(facts)
    assert "TOP_SECRET" not in str(facts)
    assert "delete_authorized" not in facts
    assert r["rca"]["cause_confirmed"] is False


def test_journal_enospc_is_evidence_from_logs_or_entries_not_confirmed_rca():
    r = report(
        vm("service_status", {"active_state": "failed", "result": "timeout"}),
        vm("system_logs", {"logs": [
            "systemd-journald: Failed to open system journal: No space left on device",
            "systemd-journald: No space left on device",
        ]}),
    )
    journal = domain(r, "journal")
    assert "Journal lines=2" in journal["technical_result"]
    assert "ENOSPC=2" in journal["technical_result"]
    assert r["rca"]["cause_confirmed"] is False
    assert "No space left on device" not in str(journal["evidence"])
