"""Incident-driven, read-only VM systemd diagnostics regression tests."""
from __future__ import annotations

from datetime import datetime, timezone

import pytest

from apps.context_service.evidence_collector import EvidenceCollector
from domain.contracts.config import settings
from integrations.vm.ssh_connector import SSHVMConnector
from integrations.vm.target_context import bind_vm_target, reset_vm_target


@pytest.mark.asyncio
async def test_failed_systemd_status_collects_full_diagnostics_even_when_status_exits_three(monkeypatch):
    connector = object.__new__(SSHVMConnector)
    seen = []

    async def fake_run(target, command):
        seen.append((target, command))
        if command.startswith("systemctl show"):
            return {
                "success": True,
                "stdout": (
                    "LoadState=loaded\nActiveState=failed\nSubState=failed\n"
                    "UnitFileState=enabled\nMainPID=0\nExecMainCode=2\n"
                    "ExecMainStatus=9\nNRestarts=0\nResult=timeout\n"
                    "TimeoutStartUSec=1min 30s\nTimeoutStopUSec=45s\n"
                ),
            }
        assert command == "LC_ALL=C systemctl status gfpapi --no-pager -l --lines=30"
        return {
            "success": False, "exit_code": 3,
            "stdout": "gfpapi.service - failed\nActive: failed (Result: timeout)\n",
        }

    monkeypatch.setattr(connector, "_run", fake_run)
    monkeypatch.setattr(settings, "SSH_ALLOWED_SERVICES", ["gfpapi"])
    result = await connector.service_status("10.248.19.82", "gfpapi")
    assert result["success"] is True
    assert result["healthy"] is False
    assert result["active_state"] == "failed"
    assert result["result"] == "timeout"
    assert result["exec_main_code"] == 2
    assert result["exec_main_status"] == 9
    assert result["timeout_start_usec"] == "1min 30s"
    assert result["timeout_stop_usec"] == "45s"
    assert "failed (Result: timeout)" in result["systemctl_status"]
    assert len(seen) == 2
    assert "--property=TimeoutStartUSec" in seen[0][1]
    assert "--property=TimeoutStopUSec" in seen[0][1]


@pytest.mark.asyncio
async def test_active_systemd_status_does_not_fetch_expensive_diagnostics(monkeypatch):
    connector = object.__new__(SSHVMConnector)
    seen = []

    async def fake_run(target, command):
        seen.append(command)
        return {"success": True, "stdout": "ActiveState=active\nSubState=running\nMainPID=100"}

    monkeypatch.setattr(connector, "_run", fake_run)
    monkeypatch.setattr(settings, "SSH_ALLOWED_SERVICES", ["gfpapi"])
    result = await connector.service_status("10.248.19.82", "gfpapi")
    assert result["healthy"] is True
    assert "systemctl_status" not in result
    assert len(seen) == 1


@pytest.mark.asyncio
async def test_journal_reads_last_150_lines_and_redacts_credentials(monkeypatch):
    connector = object.__new__(SSHVMConnector)
    seen = []

    async def fake_run(target, command):
        seen.append(command)
        return {"success": True, "stdout": (
            "first journal line\n" + "\n".join(f"line-{i}" for i in range(150))
            + "\npassword=hunter2\n"
        )}

    monkeypatch.setattr(connector, "_run", fake_run)
    monkeypatch.setattr(settings, "SSH_ALLOWED_SERVICES", ["gfpapi"])
    result = await connector.service_logs("10.248.19.82", "gfpapi")
    assert result["success"] is True
    assert result["count"] == 150
    assert result["access_mode"] == "user"
    assert "hunter2" not in repr(result)
    assert "[REDACTED]" in repr(result)
    assert seen == ["journalctl --no-pager -u gfpapi -n 150 -o short-iso"]


@pytest.mark.asyncio
async def test_journal_permission_failure_retries_read_only_noninteractive_sudo(monkeypatch):
    connector = object.__new__(SSHVMConnector)
    commands = []

    async def fake_run(target, command):
        commands.append(command)
        if not command.startswith("sudo -n "):
            return {"success": False, "exit_code": 1, "stderr": "Permission denied opening journal"}
        return {"success": True, "exit_code": 0, "stdout": "Service gfpapi timed out starting"}

    monkeypatch.setattr(connector, "_run", fake_run)
    monkeypatch.setattr(settings, "SSH_ALLOWED_SERVICES", ["gfpapi"])
    result = await connector.service_logs("10.248.19.82", "gfpapi")
    assert result["success"] is True
    assert result["access_mode"] == "sudo"
    assert result["logs"] == ["Service gfpapi timed out starting"]
    assert commands == [
        "journalctl --no-pager -u gfpapi -n 150 -o short-iso",
        "sudo -n journalctl --no-pager -u gfpapi -n 150 -o short-iso",
    ]
    assert not any("start " in cmd or "restart " in cmd or "stop " in cmd for cmd in commands)


@pytest.mark.asyncio
async def test_journal_sudo_denied_returns_auditable_error(monkeypatch):
    connector = object.__new__(SSHVMConnector)

    async def failed_run(target, command):
        return {"success": False, "exit_code": 1, "stderr": (
            "Permission denied" if not command.startswith("sudo -n") else
            "sudo: a password is required"
        )}

    monkeypatch.setattr(connector, "_run", failed_run)
    monkeypatch.setattr(settings, "SSH_ALLOWED_SERVICES", ["gfpapi"])
    result = await connector.service_logs("10.248.19.82", "gfpapi")
    assert result["success"] is False
    assert result["error"] == "journal_access_denied"
    assert result["access_mode"] == "sudo"
    assert result["exit_code"] == 1
    assert "password is required" in result["detail"]


@pytest.mark.asyncio
async def test_disallowed_service_never_runs_systemd_or_journal(monkeypatch):
    connector = object.__new__(SSHVMConnector)
    commands = []

    async def fake_run(target, command):
        commands.append(command)
        return {"success": True}

    monkeypatch.setattr(connector, "_run", fake_run)
    monkeypatch.setattr(settings, "SSH_ALLOWED_SERVICES", ["gfpapi"])
    for service in ("gfpapi;reboot", "other-service"):
        with pytest.raises((ValueError, PermissionError)):
            await connector.service_status("10.248.19.82", service)
        with pytest.raises((ValueError, PermissionError)):
            await connector.service_logs("10.248.19.82", service)
    assert commands == []


class _VM:
    def __init__(self, *, state="failed", journal_ok=True):
        self.calls = []
        self.state = state
        self.journal_ok = journal_ok

    async def service_status(self, target, service):
        self.calls.append(("service_status", target, service))
        return {
            "success": True, "active_state": self.state, "service": service,
            "result": "timeout", "systemctl_status": "Active: failed (Result: timeout)",
            "timeout_start_usec": "90s", "timeout_stop_usec": "30s",
        }

    async def service_logs(self, target, service):
        self.calls.append(("service_logs", target, service))
        if not self.journal_ok:
            return {
                "success": False, "error": "journal_access_denied",
                "detail": "sudo: a password is required",
            }
        return {
            "success": True, "access_mode": "sudo",
            "logs": [f"log {i}" for i in range(150)],
        }


@pytest.mark.asyncio
async def test_failed_service_automatically_collects_journal_without_llm_or_external_mcp():
    vm = _VM()
    collector = EvidenceCollector(vm=vm)
    token = bind_vm_target("10.248.19.82")
    try:
        result = await collector.collect_requested(
            "gfpapi", datetime.now(timezone.utc),
            [{"evidence_type": "telemetry", "reason": "systemd service status", "preferred_source": "vm"}],
        )
    finally:
        reset_vm_target(token)
    assert vm.calls == [
        ("service_status", "10.248.19.82", "gfpapi"),
        ("service_logs", "10.248.19.82", "gfpapi"),
    ]
    by_action = {
        e["raw_data"]["diagnostic"]: e for e in result["evidence"]
        if e["source"] == "vm_mcp" and e.get("raw_data", {}).get("diagnostic")
    }
    assert by_action["service_status"]["raw_data"]["timeout_start_usec"] == "90s"
    journal = by_action["service_logs"]["raw_data"]
    assert journal["count"] == 150
    assert journal["access_mode"] == "sudo"
    assert journal["entries"][-1] == "log 149"


@pytest.mark.asyncio
async def test_healthy_service_does_not_automatically_query_journal():
    vm = _VM(state="active")
    token = bind_vm_target("10.248.19.82")
    try:
        await EvidenceCollector(vm=vm).collect_requested(
            "gfpapi", datetime.now(timezone.utc),
            [{"evidence_type": "telemetry", "reason": "systemd service status", "preferred_source": "vm"}],
        )
    finally:
        reset_vm_target(token)
    assert vm.calls == [("service_status", "10.248.19.82", "gfpapi")]


@pytest.mark.asyncio
async def test_journal_permission_failure_survives_as_explicit_source_observation():
    vm = _VM(journal_ok=False)
    token = bind_vm_target("10.248.19.82")
    try:
        result = await EvidenceCollector(vm=vm).collect_requested(
            "gfpapi", datetime.now(timezone.utc),
            [{"evidence_type": "telemetry", "reason": "systemd service status", "preferred_source": "vm"}],
        )
    finally:
        reset_vm_target(token)
    assert any(
        item["source"] == "vm_mcp" and item["raw_data"]["status"] == "error"
        and item["raw_data"]["detail"] == "journal_access_denied"
        for item in result["source_observations"]
    )


@pytest.mark.asyncio
async def test_zabbix_explicit_vm_target_is_diagnosed_before_unhealthy_optional_providers():
    sequence = []
    class FastVM(_VM):
        async def service_status(self, target, service):
            sequence.append("systemctl_show")
            return await super().service_status(target, service)
        async def service_logs(self, target, service):
            sequence.append("journalctl")
            return await super().service_logs(target, service)

    class UnavailableZabbix:
        async def health_check(self):
            sequence.append("zabbix_health")
            return False

    class UnavailablePrometheus:
        async def health_check(self):
            sequence.append("prometheus_health")
            return False

    class UnavailableElastic:
        async def health_check(self):
            sequence.append("elastic_health")
            return False

    vm = FastVM()
    token = bind_vm_target("10.248.19.82")
    try:
        result = await EvidenceCollector(
            vm=vm, zabbix=UnavailableZabbix(),
            prometheus=UnavailablePrometheus(), elasticsearch=UnavailableElastic(),
        ).collect("gfpapi", datetime.now(timezone.utc))
    finally:
        reset_vm_target(token)

    assert sequence[:2] == ["systemctl_show", "journalctl"]
    assert sequence.count("systemctl_show") == 1
    assert sequence.count("journalctl") == 1
    assert any(item["raw_data"].get("diagnostic") == "service_logs"
               for item in result["evidence"])
