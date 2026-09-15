from datetime import datetime, timezone

import pytest

from apps.context_service.evidence_collector import EvidenceCollector
from integrations.vm.service_adapters import get_service_adapter
from integrations.vm.ssh_connector import SSHVMConnector
from integrations.vm.target_context import (
    bind_vm_port,
    bind_vm_target,
    reset_vm_port,
    reset_vm_target,
    target_port_from_zabbix_payload,
)


class _DiagnosticVM:
    def __init__(self):
        self.calls = []

    async def collect_vm_metrics(self, target):
        self.calls.append(("collect_vm_metrics", target))
        return {"success": True, "metrics": {"cpu_usage": 1.0}}

    async def collect_metrics(self, target):
        self.calls.append(("collect_vm_metrics", target))
        return {"success": True, "metrics": {"cpu_usage": 1.0}}

    async def host_info(self, target):
        self.calls.append(("host_info", target))
        return {"success": True, "host": {"hostname": "NeoBanking-6.199"}}

    async def disk_status(self, target):
        self.calls.append(("disk_status", target))
        return {"success": True, "filesystems": [], "inodes": []}

    async def service_status(self, target, service):
        self.calls.append(("service_status", target, service))
        return {"success": True, "active_state": "active", "sub_state": "running"}

    async def process_status(self, target, process):
        self.calls.append(("process_status", target, process))
        return {"success": True, "process": process, "running": True, "processes": [{"pid": 10}]}

    async def port_listener_status(self, target, port):
        self.calls.append(("port_listener_status", target, port))
        return {"success": True, "port": port, "listening": False, "listeners": []}

    async def tcp_check(self, target, host, port):
        self.calls.append(("tcp_check", target, host, port))
        return {"success": True, "host": host, "port": port, "reachable": False}

    async def service_logs(self, target, service):
        self.calls.append(("service_logs", target, service))
        return {"success": True, "logs": ["haproxy log line"], "count": 1}

    async def config_validate(self, target, service):
        self.calls.append(("config_validate", target, service))
        return {"success": True, "supported": True, "valid": True}


class _UnavailableElastic:
    async def health_check(self):
        return False


@pytest.mark.asyncio
async def test_semantic_vm_evidence_requests_use_diagnostic_tools_not_generic_metrics():
    vm = _DiagnosticVM()
    collector = EvidenceCollector(vm=vm, elasticsearch=_UnavailableElastic())
    target_token = bind_vm_target("10.100.6.199")
    port_token = bind_vm_port(8800)
    try:
        result = await collector.collect_requested(
            "haproxy",
            datetime.now(timezone.utc),
            [
                {"evidence_type": "telemetry", "reason": "HAProxy process status", "preferred_source": "vm"},
                {"evidence_type": "telemetry", "reason": "Port 8800 binding status", "preferred_source": "vm"},
                {"evidence_type": "log", "reason": "HAProxy service logs", "preferred_source": "elasticsearch"},
            ],
        )
    finally:
        reset_vm_port(port_token)
        reset_vm_target(target_token)

    assert ("process_status", "10.100.6.199", "haproxy") in vm.calls
    assert ("port_listener_status", "10.100.6.199", 8800) in vm.calls
    assert ("tcp_check", "10.100.6.199", "10.100.6.199", 8800) in vm.calls
    assert ("service_logs", "10.100.6.199", "haproxy") in vm.calls
    assert not any(call[0] == "collect_vm_metrics" for call in vm.calls)
    assert all("haproxy" != call[1] for call in vm.calls)

    diagnostics = {
        item.get("raw_data", {}).get("diagnostic")
        for item in result["evidence"]
        if item.get("source") == "vm_mcp"
    }
    assert {"process_status", "port_listener_status", "tcp_check", "service_logs"}.issubset(diagnostics)


@pytest.mark.asyncio
async def test_initial_vm_collection_proactively_checks_service_config_and_trigger_port():
    vm = _DiagnosticVM()
    collector = EvidenceCollector(vm=vm)
    target_token = bind_vm_target("10.100.6.199")
    port_token = bind_vm_port(8800)
    try:
        await collector.collect("haproxy", datetime.now(timezone.utc))
    finally:
        reset_vm_port(port_token)
        reset_vm_target(target_token)

    assert ("service_status", "10.100.6.199", "haproxy") in vm.calls
    assert ("process_status", "10.100.6.199", "haproxy") in vm.calls
    assert ("config_validate", "10.100.6.199", "haproxy") in vm.calls
    assert ("port_listener_status", "10.100.6.199", 8800) in vm.calls
    assert ("tcp_check", "10.100.6.199", "10.100.6.199", 8800) in vm.calls


def test_target_port_resolution_accepts_only_explicit_valid_port():
    assert target_port_from_zabbix_payload({"target_port": 8800, "trigger": "port 9999 down"}) == 8800
    assert target_port_from_zabbix_payload({"trigger": "port 8800 down"}) is None
    assert target_port_from_zabbix_payload({"target_port": 0}) is None
    assert target_port_from_zabbix_payload({"target_port": 70000}) is None
    assert target_port_from_zabbix_payload({"target_port": "not-a-port"}) is None


def test_service_adapter_uses_fixed_haproxy_validation_command():
    adapter = get_service_adapter("haproxy")
    assert adapter is not None
    assert adapter.config_check_command == "haproxy -c -f /etc/haproxy/haproxy.cfg"
    assert get_service_adapter("anything;rm -rf /") is None


@pytest.mark.asyncio
async def test_structured_service_status_parses_systemd_properties(monkeypatch):
    connector = object.__new__(SSHVMConnector)

    async def fake_run(target, command):
        assert target == "10.100.6.199"
        assert command.startswith("systemctl show --no-pager")
        return {
            "success": True,
            "stdout": "LoadState=loaded\nActiveState=active\nSubState=running\nUnitFileState=enabled\nMainPID=123\nExecMainStatus=0\nNRestarts=2\nResult=success",
        }

    monkeypatch.setattr(connector, "_run", fake_run)
    monkeypatch.setattr(connector, "_validate_service", lambda service: None)
    result = await connector.service_status("10.100.6.199", "haproxy")

    assert result["active_state"] == "active"
    assert result["sub_state"] == "running"
    assert result["unit_file_state"] == "enabled"
    assert result["main_pid"] == 123
    assert result["restart_count"] == 2
    assert result["healthy"] is True


@pytest.mark.asyncio
async def test_reload_is_fixed_governed_service_command(monkeypatch):
    connector = object.__new__(SSHVMConnector)
    captured = {}

    async def fake_run(target, command):
        captured.update(target=target, command=command)
        return {"success": True}

    monkeypatch.setattr(connector, "_run", fake_run)
    monkeypatch.setattr(connector, "_validate_service", lambda service: None)
    result = await connector.reload_service("10.100.6.199", "haproxy")

    assert result["success"] is True
    assert captured == {"target": "10.100.6.199", "command": "sudo -n systemctl reload haproxy"}
