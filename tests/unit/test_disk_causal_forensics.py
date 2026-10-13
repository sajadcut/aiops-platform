"""Disk-pressure RCA tests: no age-based cleanup, no write authority."""
from datetime import datetime, timezone

import pytest

from agents.storage.engine import correlate_disk_file_causality, build_storage_reliability_analysis
from apps.context_service.evidence_collector import EvidenceCollector
from apps.context_service.llm_identity import detect_operational_unknowns
from apps.decision_brief import build_decision_brief
from domain.contracts.config import settings
from integrations.vm.ssh_connector import SSHVMConnector
from integrations.vm.target_context import bind_vm_target, reset_vm_target


@pytest.mark.asyncio
async def test_vm_disk_forensics_is_read_only_and_bounded(monkeypatch):
    monkeypatch.setattr(settings, "APP_ENV", "test")
    monkeypatch.setattr(settings, "SSH_AUTH_MODE", "key")
    connector = SSHVMConnector()
    called = []

    async def disk_status(target):
        return {"success": True, "target": target, "filesystems": [
            {"mount": "/", "use_percent": "98%"},
            {"mount": "/proc", "use_percent": "100%"},
            {"mount": "/data", "use_percent": "95%"},
            {"mount": "/backup", "use_percent": "70%"},
        ], "inodes": []}

    async def fake_run(target, command):
        called.append(command)
        assert not any(word in command for word in (" rm ", "unlink ", "truncate ", "delete "))
        if "stat --printf" in command:
            assert "sleep 2" in command
            assert "lsof -nP" in command
            return {"success": True, "stdout": (
                "123\t36000000000\t/var/log/gfpapi/error.log\n"
                "__AIOPS_STAT_SECOND__\n"
                "123\t36700160000\t/var/log/gfpapi/error.log\n"
                "__AIOPS_LSOF__\n"
                "p2020\ncgfpapi\nf2w\nn/var/log/gfpapi/error.log\n"
            )}
        assert "find" in command and "-xdev" in command
        assert "timeout 12s" in command
        return {"success": True, "stdout": "36700160000\t1791882600.0\t/var/log/gfpapi/error.log\n"}

    monkeypatch.setattr(connector, "disk_status", disk_status)
    monkeypatch.setattr(connector, "_run", fake_run)
    result = await connector.disk_forensics("10.100.6.199")
    assert result["success"] is True
    assert result["delete_authorized"] is False
    assert result["growth_measured"] is True
    assert result["content_inspected"] is False
    assert len(called) == 4
    assert not any("/proc" in command or "/backup" in command for command in called)
    assert len(result["mounts"]) == 2
    sampled = result["mounts"][0]["files"][0]
    assert sampled["growth_confirmed"] is True
    assert sampled["growth_bytes_over_2_seconds"] == 700160000
    assert sampled["open_handles"][0]["pid"] == 2020
    assert sampled["open_handles"][0]["writable_handle_observed"] is True
    assert sampled["open_handles"][0]["writer_causality_verified"] is False
    assert all(file["safe_to_delete"] is not True if "safe_to_delete" in file else True
               for mount in result["mounts"] for file in mount["files"])
    assert all(file["retention_policy_verified"] is False for mount in result["mounts"]
               for file in mount["files"])


def _file_evidence():
    return {
        "source": "vm_mcp", "reference": "disk1",
        "type": "telemetry", "timestamp": "2026-10-13T12:00:00Z",
        "raw_data": {
            "diagnostic": "disk_forensics", "success": True,
            "mounts": [{"mount": "/var", "used_percent": 98, "files": [
                {"path": "/var/log/gfpapi/error.log", "size_bytes": 37000000000,
                 "mtime_epoch": 1791882600.0, "growth_measured": True,
                 "growth_confirmed": True, "growth_bytes_over_2_seconds": 700160000,
                 "open_handles": [{"pid": 2020, "process_name": "gfpapi",
                                   "writable_handle_observed": True,
                                   "writer_causality_verified": False}]},
            ]}],
        },
    }


def test_file_inventory_is_not_proof_of_writer_growth_or_safe_deletion():
    evidence = [
        _file_evidence(),
        {"source": "elasticsearch", "reference": "elastic1",
         "timestamp": "2026-10-13T12:05:00Z",
         "raw_data": {"message": "backend request failed repeatedly"}},
        {"source": "zabbix", "reference": "zbx1",
         "timestamp": "2026-10-13T12:06:00Z",
         "raw_data": {"event": "disk 98% full"}},
    ]
    result = correlate_disk_file_causality(evidence)
    assert result["files"][0]["path"] == "/var/log/gfpapi/error.log"
    assert result["files"][0]["causal_attribution"] == "unknown"
    assert result["files"][0]["growth_confirmed"] is True
    assert result["files"][0]["growth_bytes_over_2_seconds"] == 700160000
    assert result["files"][0]["open_handles"][0]["process_name"] == "gfpapi"
    assert result["files"][0]["open_handles"][0]["writer_causality_verified"] is False
    assert result["measured_growing_files"] == 1
    assert result["files_with_open_handles"] == 1
    assert result["files"][0]["safe_to_delete"] is False
    assert result["delete_recommendation_allowed"] is False
    assert result["safe_cleanup_candidates"] == []
    assert result["growth_cause_confirmed"] is False
    assert result["related_error_log_observations"][0]["reference"] == "elastic1"
    assert result["zabbix_alert_refs"] == ["zbx1"]
    assert "retention" in result["missing_for_deletion"][2]
    summary = build_storage_reliability_analysis(evidence, service_name="gfpapi")
    assert summary["disk_file_causality"]["delete_recommendation_allowed"] is False
    assert "file producer" in summary["disk_file_causality"]["recommended_investigation"]


def test_llm_is_asked_about_unknown_disk_growth_not_automatic_cleanup():
    gap = detect_operational_unknowns([_file_evidence()])
    assert len(gap) == 1
    assert gap[0]["topic"] == "disk_file_growth_cause_unknown"
    assert gap[0]["subject"] == "/var"


@pytest.mark.asyncio
async def test_disk_pressure_triggers_forensics_but_lower_pressure_does_not(monkeypatch):
    class VM:
        def __init__(self, used):
            self.used = used
            self.calls = []
        async def disk_status(self, target):
            self.calls.append("disk_status")
            return {"success": True, "filesystems": [
                {"mount": "/var", "use_percent": str(self.used) + "%"}
            ], "inodes": []}
        async def disk_forensics(self, target):
            self.calls.append("disk_forensics")
            return _file_evidence()["raw_data"]
        async def host_info(self, target):
            return {"success": True, "host": {"hostname": "test"}}
        async def collect_vm_metrics(self, target):
            return {"success": True, "metrics": {}}
        async def collect_metrics(self, target):
            return {"success": True, "metrics": {}}
    for used, should_scan in ((89, False), (98, True)):
        vm = VM(used)
        token = bind_vm_target("10.100.6.199")
        try:
            result = await EvidenceCollector(vm=vm).collect(
                "gfpapi", datetime.now(timezone.utc)
            )
        finally:
            reset_vm_target(token)
        assert ("disk_forensics" in vm.calls) is should_scan
        if should_scan:
            assert any(x.get("raw_data", {}).get("diagnostic") == "disk_forensics"
                       for x in result["evidence"])


def test_disk_report_makes_no_cleanup_approval_or_write_authority():
    report = build_decision_brief(
        incident={"id": "disk-1", "service": "gfpapi", "status": "analyzing"},
        operator_summary={},
        checkpoint={"state": {}}, durable_evidence=[_file_evidence()],
        findings=[], audit_events=[],
    )
    assert report["disk_file_causality"]["files"][0]["path"] == "/var/log/gfpapi/error.log"
    assert report["disk_file_causality"]["delete_recommendation_allowed"] is False
    assert report["source_policy"]["authorizes_execution"] is False
