"""Acceptance: a host RAM incident must explain checks and gaps without invented RCA."""
from datetime import datetime, timezone

import pytest

from apps.incident_memory_forensics import build_memory_investigation
from apps.context_service.evidence_collector import EvidenceCollector
from integrations.vm.ssh_connector import SSHVMConnector
from integrations.vm.target_context import bind_vm_target, reset_vm_target


def incident():
    return {
        "service": "unknown",
        "summary": "High memory utilization (>90% for 5m)",
        "status": "resolved",
        "context": {"host_name": "APORSDTNKSA0101"},
    }


def checkpoint(*, target=None):
    return {"state": {"context": {"trigger_signal": {
        "source": "zabbix", "summary": "High memory utilization (>90% for 5m)",
        "raw_data": {
            "host_name": "APORSDTNKSA0101",
            **({"target_ip": target} if target else {}),
        },
    }}}}


def audit():
    return [{
        "event_type": "verification_source_recovery_received",
        "actor": "zabbix_webhook",
        "created_at": "2026-10-14T09:35:00Z",
    }]


def vm_row(diag, raw, at="2026-10-14T09:30:00Z", target="10.248.41.67"):
    return {
        "source": "vm_mcp", "type": "telemetry",
        "reference": "vm:" + target + ":" + diag,
        "created_at": at,
        "raw_data": {"diagnostic": diag, "target": target,
                     "success": True, **raw},
    }


def test_memory_alert_recovery_is_not_execution_verification():
    report = build_memory_investigation(
        incident=incident(), checkpoint=checkpoint(), evidence=[],
        audit_events=audit(),
    )
    assert report["kind"] == "host_memory_investigation"
    assert report["alert"]["threshold_percent"] == 90
    assert report["alert"]["duration_minutes"] == 5
    assert report["alert"]["recovery_received"] is True
    assert report["alert"]["recovery_time"] == "2026-10-14T09:35:00+00:00"
    assert report["root_cause_status"] == "not_proven"
    assert report["source_recovery_not_action_verification"] is True
    assert report["target_binding_missing"] is True
    assert all(x["status"] == "not_collected" for x in report["checks"])
    assert report["measurements"]["top_processes"] == []
    assert all(x["type"] != "write" for x in report["recommended_next_checks"])
    assert "Restart" in report["recommended_next_checks"][-1]["detail_fa"]


def test_real_vm_diagnostic_shows_top_consumers_as_snapshots_not_rca():
    evidence = [
        vm_row("memory_diagnostics", {
            "used_percent": 92.7, "total_mb": 16000, "available_mb": 1200,
            "cache_reclaimable_mb": 600, "swap_total_mb": 2048,
            "swap_used_mb": 1500, "psi_memory_some_avg10": 12.4,
            "top_processes": [
                {"pid": 123, "command": "dotnet", "rss_mb": 5000,
                 "memory_percent": 31.5},
                {"pid": 77, "command": "postgres", "rss_mb": 2048,
                 "memory_percent": 12.8},
            ],
        }),
        vm_row("collect_vm_metrics", {"name": "memory_usage", "value": 93.2}),
        vm_row("memory_diagnostics", {"used_percent": 100}, target="10.248.41.68",
               at="2026-10-14T09:33:00Z"),
    ]
    result = build_memory_investigation(
        incident=incident(), checkpoint=checkpoint(target="10.248.41.67"),
        evidence=evidence, audit_events=[],
    )
    assert result["measurements"]["memory_used_percent"] == 92.7
    assert result["measurements"]["top_processes"][0]["name"] == "dotnet"
    assert result["measurements"]["top_processes"][0]["rss_mb"] == 5000
    assert result["root_cause_status"] == "not_proven"
    assert result["checks"][1]["status"] == "checked"
    assert result["checks"][1]["evidence_refs"]
    assert result["target_binding_missing"] is False


def test_unrelated_service_alarm_has_no_host_ram_card():
    x = {"service": "gfpapi", "summary": "GFPAPI Systemd Service Down"}
    assert build_memory_investigation(
        incident=x, checkpoint={}, evidence=[], audit_events=[]) is None


@pytest.mark.asyncio
async def test_remote_memory_diagnostics_reads_only_proc_metrics_and_sorts_rss(monkeypatch):
    connector = object.__new__(SSHVMConnector)
    async def run(target, command):
        assert target == "10.248.41.67"
        assert "/proc/meminfo" in command
        assert "--sort=-rss" in command
        assert "sudo" not in command
        assert "python" not in command
        return {
            "success": True, "stdout": (
                "MEMORY_BEGIN\nMemTotal: 16384000\nMemAvailable: 1638400\n"
                "Cached: 2048000\nSReclaimable: 512000\n"
                "SwapTotal: 2097152\nSwapFree: 524288\nMEMORY_END\n"
                "PROCESS_BEGIN\n123 1 dotnet 4096000 25.0\n"
                "77 1 postgres 1024000 6.25\nPROCESS_END\n"
                "PRESSURE_BEGIN\navg10=10.50\nPRESSURE_END\n"
            )
        }
    monkeypatch.setattr(connector, "_run", run)
    data = await connector.memory_diagnostics("10.248.41.67")
    assert data["success"] is True
    assert data["used_percent"] == 90.0
    assert data["cache_reclaimable_mb"] == 2500
    assert data["swap_used_mb"] == 1536
    assert data["psi_memory_some_avg10"] == 10.5
    assert data["top_processes"][0]["rss_mb"] == 4000
    assert data["reason_cannot_be_proven_from_single_snapshot"] is True


class DummyMemoryVM:
    def __init__(self):
        self.calls = []

    async def collect_vm_metrics(self, target):
        self.calls.append("collect_vm_metrics")
        return {"success": True, "metrics": {"memory_usage": 93.12}}

    async def host_info(self, target):
        self.calls.append("host_info")
        return {"success": True, "hostname": "APORSDTNKSA0101"}

    async def disk_status(self, target):
        self.calls.append("disk_status")
        return {"success": True, "filesystems": []}

    async def memory_diagnostics(self, target):
        self.calls.append("memory_diagnostics")
        return {"success": True, "used_percent": 92.1,
                "total_mb": 16000, "available_mb": 1264,
                "top_processes": []}

    async def process_snapshot(self, target):
        self.calls.append("process_snapshot")
        return {"success": True, "processes": []}


@pytest.mark.asyncio
async def test_unknown_service_host_collects_ram_evidence_without_systemd_name():
    vm = DummyMemoryVM()
    collector = EvidenceCollector(vm=vm)
    token = bind_vm_target("10.248.41.67")
    try:
        result = await collector.collect("unknown", datetime.now(timezone.utc))
    finally:
        reset_vm_target(token)
    assert "memory_diagnostics" in vm.calls
    assert "process_snapshot" in vm.calls
    assert not any(x in vm.calls for x in ["service_status", "config_validate"])
    raw = [x["raw_data"] for x in result["evidence"]
           if x.get("source") == "vm_mcp"]
    assert any(x.get("diagnostic") == "memory_diagnostics" for x in raw)


@pytest.mark.asyncio
async def test_without_explicit_vm_target_no_remote_probe():
    vm = DummyMemoryVM()
    result = await EvidenceCollector(vm=vm).collect(
        "unknown", datetime.now(timezone.utc))
    assert vm.calls == []
    assert not any(x.get("source") == "vm_mcp" and x.get("type") != "source_observation"
                   for x in result["evidence"])
