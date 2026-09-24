import pytest

import apps.mcp_server.main as mcp_server
from domain.contracts.config import settings
from integrations.mcp_client import MCPClient
from integrations.vm.mcp_client import VMEdgeMCPClient
from integrations.vm.ssh_connector import SSHVMConnector


def test_vm_target_and_service_allowlists(monkeypatch):
    monkeypatch.setattr(settings, "APP_ENV", "test")
    monkeypatch.setattr(settings, "SSH_ALLOWED_TARGETS", ["vm01"])
    monkeypatch.setattr(settings, "SSH_ALLOWED_SERVICES", ["nginx", "haproxy"])
    connector = SSHVMConnector()
    connector._validate_target("vm01")
    connector._validate_service("nginx")
    connector._validate_service("haproxy")
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
async def test_vm_mcp_write_requires_approval_and_incident_context(monkeypatch):
    monkeypatch.setattr(settings, "APP_ENV", "test")
    monkeypatch.setattr(mcp_server, "SSHVMConnector", _FakeVMConnector)
    _FakeVMConnector.calls = 0

    args = {
        "target": "vm01",
        "service": "nginx",
        "approval_id": "approval-1",
        "incident_id": "incident-1",
    }
    result = await mcp_server._call("vm", "restart_service", args)
    assert result["success"] is True
    assert _FakeVMConnector.calls == 1

    with pytest.raises(PermissionError, match="approval_id_required"):
        await mcp_server._call("vm", "restart_service", {"target": "vm01", "service": "nginx", "incident_id": "incident-1"})
    with pytest.raises(PermissionError, match="incident_id_required"):
        await mcp_server._call("vm", "restart_service", {"target": "vm01", "service": "nginx", "approval_id": "approval-1"})
    assert _FakeVMConnector.calls == 1


@pytest.mark.asyncio
async def test_vm_mcp_rejects_wrong_server_identity(monkeypatch):
    monkeypatch.setattr(settings, "VM_MCP_URL", "http://127.0.0.1:9104/mcp")
    monkeypatch.setattr(settings, "MCP_BEARER_TOKEN", "test-control-plane-token")

    async def fake_initialize(self):
        self._initialized = True
        return {
            "protocolVersion": settings.MCP_PROTOCOL_VERSION,
            "serverInfo": {"name": "aiops-elasticsearch-mcp", "version": settings.APP_VERSION},
        }

    monkeypatch.setattr(MCPClient, "initialize", fake_initialize)
    client = VMEdgeMCPClient()
    try:
        with pytest.raises(RuntimeError, match="mcp_server_identity_mismatch:vm-edge"):
            await client.initialize()
    finally:
        await client.close()
