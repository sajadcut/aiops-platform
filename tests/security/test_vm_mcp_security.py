import pytest

import apps.mcp_server.main as mcp_server
from apps.execution_service.capability import issue_execution_capability
from domain.contracts.config import settings
from integrations.vm.ssh_connector import SSHVMConnector


def test_vm_target_and_service_allowlists(monkeypatch):
    monkeypatch.setattr(settings, "APP_ENV", "test")
    monkeypatch.setattr(settings, "SSH_ALLOWED_TARGETS", ["vm01"])
    monkeypatch.setattr(settings, "SSH_ALLOWED_SERVICES", ["nginx"])
    connector = SSHVMConnector()
    connector._validate_target("vm01")
    connector._validate_service("nginx")
    with pytest.raises(PermissionError):
        connector._validate_target("vm02")
    with pytest.raises(PermissionError):
        connector._validate_service("postgresql")


def test_production_vm_edge_rejects_root_and_missing_host_pinning(monkeypatch):
    monkeypatch.setattr(settings, "APP_ENV", "production")
    monkeypatch.setattr(settings, "SSH_ENABLED", True)
    monkeypatch.setattr(settings, "SSH_USERNAME", "root")
    monkeypatch.setattr(settings, "SSH_PRIVATE_KEY_PATH", "/secrets/id_ed25519")
    monkeypatch.setattr(settings, "SSH_KNOWN_HOSTS", None)
    monkeypatch.setattr(settings, "SSH_STRICT_HOST_KEY_CHECKING", False)
    monkeypatch.setattr(settings, "SSH_ALLOWED_TARGETS", ["vm01"])
    monkeypatch.setattr(settings, "SSH_ALLOWED_SERVICES", ["nginx"])
    with pytest.raises(RuntimeError) as exc:
        SSHVMConnector()
    message = str(exc.value)
    assert "root SSH is forbidden" in message
    assert "SSH_KNOWN_HOSTS is required" in message
    assert "SSH_STRICT_HOST_KEY_CHECKING must be true" in message


class _FakeVMConnector:
    calls = 0

    async def restart_service(self, target, service):
        _FakeVMConnector.calls += 1
        return {"success": True, "target": target, "service": service}


@pytest.mark.asyncio
async def test_vm_mcp_requires_bound_capability_and_rejects_replay(monkeypatch):
    monkeypatch.setattr(settings, "APP_ENV", "test")
    monkeypatch.setenv("EXECUTION_CAPABILITY_SECRET", "test-execution-capability-secret-32-bytes-minimum")
    monkeypatch.setattr(mcp_server, "SSHVMConnector", _FakeVMConnector)
    mcp_server._CONSUMED_CAPABILITIES.clear()
    _FakeVMConnector.calls = 0

    capability = issue_execution_capability(
        incident_id="incident-1",
        approval_id="approval-1",
        tool_name="ssh_vm",
        action="restart_service",
        target="vm01",
        parameters={"service": "nginx"},
        timeout=30,
    )
    args = {
        "target": "vm01",
        "service": "nginx",
        "approval_id": "approval-1",
        "incident_id": "incident-1",
        "execution_capability": capability,
    }
    result = await mcp_server._call("vm", "restart_service", args)
    assert result["success"] is True
    assert _FakeVMConnector.calls == 1

    with pytest.raises(PermissionError, match="execution_capability_replayed"):
        await mcp_server._call("vm", "restart_service", args)
    assert _FakeVMConnector.calls == 1


@pytest.mark.asyncio
async def test_vm_mcp_rejects_capability_bound_to_different_target(monkeypatch):
    monkeypatch.setattr(settings, "APP_ENV", "test")
    monkeypatch.setenv("EXECUTION_CAPABILITY_SECRET", "test-execution-capability-secret-32-bytes-minimum")
    monkeypatch.setattr(mcp_server, "SSHVMConnector", _FakeVMConnector)
    mcp_server._CONSUMED_CAPABILITIES.clear()
    capability = issue_execution_capability(
        incident_id="incident-1",
        approval_id="approval-1",
        tool_name="ssh_vm",
        action="restart_service",
        target="vm01",
        parameters={"service": "nginx"},
        timeout=30,
    )
    with pytest.raises(PermissionError, match="execution_capability_target_mismatch"):
        await mcp_server._call("vm", "restart_service", {
            "target": "vm02",
            "service": "nginx",
            "approval_id": "approval-1",
            "incident_id": "incident-1",
            "execution_capability": capability,
        })
