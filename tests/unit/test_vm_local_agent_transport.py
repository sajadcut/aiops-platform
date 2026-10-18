"""Contract and security regression tests for optional SSH-free VM edge agents."""
from __future__ import annotations

import pytest

from domain.contracts.config import settings
from integrations.mcp_client import MCPClient
from integrations.vm.local_agent_connector import LocalVMConnector
from integrations.vm.mcp_client import VMEdgeMCPClient, vm_transport_configured
from apps.mcp_server.main import _TOOL_SCHEMAS, _call


@pytest.fixture
def agent_settings(monkeypatch):
    monkeypatch.setattr(settings, "APP_ENV", "test")
    monkeypatch.setattr(settings, "SSH_ENABLED", False)
    monkeypatch.setattr(settings, "VM_AGENT_TARGET", "vm-01")
    monkeypatch.setattr(settings, "VM_AGENT_ALLOWED_SERVICES", ["nginx", "gfpapi"])
    monkeypatch.setattr(settings, "VM_EXECUTION_BACKEND", "agent")
    monkeypatch.setattr(settings, "VM_AGENT_ENDPOINTS", {
        "vm-01": "https://vm-01.example.internal/mcp",
        "vm-02": "https://vm-02.example.internal/mcp",
    })
    monkeypatch.setattr(settings, "VM_AGENT_TOKENS", {
        "vm-01": "A" * 40, "vm-02": "B" * 40,
    })
    monkeypatch.setattr(settings, "VM_AGENT_BEARER_TOKEN", "A" * 40)


def test_agent_has_complete_vm_tool_contract():
    assert _TOOL_SCHEMAS["vm_agent"] == _TOOL_SCHEMAS["vm"]
    assert set(_TOOL_SCHEMAS["vm_agent"]) == VMEdgeMCPClient.READ_TOOLS | VMEdgeMCPClient.WRITE_TOOLS
    assert not {"shell", "execute_command", "powershell", "ssh"} & set(_TOOL_SCHEMAS["vm_agent"])


@pytest.mark.asyncio
async def test_local_connector_executes_on_host_without_ssh(agent_settings):
    connector = LocalVMConnector()
    assert connector.source_name == "vm_agent"
    result = await connector._run("vm-01", "printf local_probe")
    assert result["success"] is True
    assert result["stdout"] == "local_probe"


@pytest.mark.asyncio
async def test_agent_rejects_wrong_target_and_service(agent_settings):
    connector = LocalVMConnector()
    with pytest.raises(PermissionError, match="vm_target_not_allowed"):
        await connector._run("vm-02", "printf prohibited")
    with pytest.raises(PermissionError, match="vm_service_not_allowed"):
        await connector.service_status("vm-01", "unknown")


def test_agent_refuses_ssh_enabled(agent_settings, monkeypatch):
    monkeypatch.setattr(settings, "SSH_ENABLED", True)
    with pytest.raises(RuntimeError, match="vm_agent_must_not_enable_ssh"):
        LocalVMConnector()


@pytest.mark.asyncio
async def test_agent_requires_approval_context_for_service_writes(agent_settings):
    with pytest.raises(PermissionError, match="approval_id_required"):
        await _call("vm_agent", "restart_service", {"target": "vm-01", "service": "nginx"})


@pytest.mark.asyncio
async def test_api_routes_to_configured_target_and_never_falls_back(agent_settings, monkeypatch):
    observed = []

    async def fake_call_tool(self, name, args):
        observed.append((self.server_url, self.EXPECTED_SERVER_NAME, self.bearer_token, name, args.copy()))
        return {"content": [{"success": True, "target": args["target"]}]}

    monkeypatch.setattr(MCPClient, "call_tool", fake_call_tool)
    assert vm_transport_configured()
    client = VMEdgeMCPClient()
    result = await client.service_status("vm-02", "nginx")
    assert result == {"success": True, "target": "vm-02"}
    assert observed == [(
        "https://vm-02.example.internal/mcp",
        "aiops-vm-agent-mcp",
        "B" * 40,
        "service_status",
        {"target": "vm-02", "service": "nginx"},
    )]
    with pytest.raises(PermissionError, match="vm_target_not_allowed"):
        await client.service_status("unregistered", "nginx")
    assert len(observed) == 1


def test_transport_switch_preserves_legacy_ssh_mode(agent_settings, monkeypatch):
    monkeypatch.setattr(settings, "VM_EXECUTION_BACKEND", "ssh")
    monkeypatch.setattr(settings, "VM_MCP_URL", "http://localhost:9105/mcp")
    client = VMEdgeMCPClient()
    assert client.server_url == "http://localhost:9105/mcp"
    assert client.EXPECTED_SERVER_NAME == "aiops-vm-mcp"


def test_agent_claim_key_is_isolated_from_other_targets(agent_settings, monkeypatch):
    from apps.config_change_authorization import create_claim, verify_claim
    monkeypatch.setattr(settings, "MCP_SERVER_PROVIDER", "elasticsearch")
    claims, signature = create_claim(
        approval_id="approved-1", incident_id="incident-1", target="vm-01",
        service="nginx", config_file="/etc/nginx/nginx.conf",
        original_sha256="a" * 64, candidate_sha256="b" * 64,
        proposed_change="remove_extra_opening_brace",
    )
    monkeypatch.setattr(settings, "MCP_SERVER_PROVIDER", "vm_agent")
    monkeypatch.setattr(settings, "VM_AGENT_BEARER_TOKEN", "A" * 40)
    verify_claim(claims, signature, target="vm-01", service="nginx")
    monkeypatch.setattr(settings, "VM_AGENT_BEARER_TOKEN", "B" * 40)
    with pytest.raises(PermissionError, match="config_execution_claim_signature_invalid"):
        verify_claim(claims, signature, target="vm-01", service="nginx")


@pytest.mark.asyncio
async def test_health_checks_all_agent_targets_not_only_first(agent_settings, monkeypatch):
    seen = []

    async def fake_health(self):
        seen.append(self.server_url)
        return self.server_url.endswith("vm-01.example.internal/mcp")

    monkeypatch.setattr(MCPClient, "health_check", fake_health)
    client = VMEdgeMCPClient()
    assert await client.health_check() is False
    assert set(seen) == set(settings.VM_AGENT_ENDPOINTS.values())
    await client.close()
