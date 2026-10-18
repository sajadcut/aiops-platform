"""Agent sudo credentials: per-target WSS bootstrap, in-memory use and zero disclosure."""
from __future__ import annotations

import asyncio
import json
import time
from unittest.mock import AsyncMock

import pytest

from apps.api.vm_agent_broker import OutboundAgentBroker
from domain.contracts.config import settings
from vmmcpagent.connector import LocalVMConnector
from tests.unit.test_vm_outbound_agent import FakeSocket


@pytest.fixture
def provision(monkeypatch):
    monkeypatch.setattr(settings, "VM_EXECUTION_BACKEND", "agent_pull")
    monkeypatch.setattr(settings, "APP_ENV", "production")
    monkeypatch.setattr(settings, "VM_AGENT_TOKENS", {"vm-01": "A" * 40, "vm-02": "B" * 40})
    monkeypatch.setattr(settings, "VM_AGENT_EXECUTION_CREDENTIALS", {
        "vm-01": {"username": "opsbot", "password": "sudo-secret-one"},
        "vm-02": {"username": "operator2", "password": "sudo-secret-two"},
    })
    monkeypatch.setattr(settings, "VM_AGENT_EXEC_USERNAME", "opsbot")
    monkeypatch.setattr(settings, "VM_AGENT_TARGET", "vm-01")
    monkeypatch.setattr(settings, "SSH_ENABLED", False)
    monkeypatch.setattr(settings, "VM_AGENT_ALLOWED_SERVICES", ["nginx"])


@pytest.mark.asyncio
async def test_authenticated_agent_gets_only_its_own_bootstrap_credentials(provision):
    hub = OutboundAgentBroker()
    vm1 = FakeSocket("A" * 40)
    connection = asyncio.create_task(hub.connect(vm1, "vm-01"))
    first = await asyncio.wait_for(vm1.outbound.get(), 1)
    assert first == {"type": "credentials", "version": 1, "target": "vm-01",
                     "username": "opsbot", "password": "sudo-secret-one"}
    assert not hub.is_connected("vm-01")
    await vm1.inbound.put(json.dumps({
        "type": "credentials_ack", "target": "vm-01", "username": "opsbot", "ok": True,
    }))
    for _ in range(100):
        if hub.is_connected("vm-01"):
            break
        await asyncio.sleep(.001)
    assert hub.is_connected("vm-01")
    task = asyncio.create_task(hub.dispatch(
        "vm-01", "service_status", {"target": "vm-01", "service": "nginx"}
    ))
    issued = await asyncio.wait_for(vm1.outbound.get(), 1)
    assert issued["type"] == "execute"
    assert "sudo-secret-one" not in json.dumps(issued)
    await vm1.result(issued, {"success": True})
    assert (await task)["success"] is True

    vm2 = FakeSocket("B" * 40)
    second = asyncio.create_task(hub.connect(vm2, "vm-02"))
    nextframe = await asyncio.wait_for(vm2.outbound.get(), 1)
    assert nextframe["password"] == "sudo-secret-two"
    assert "sudo-secret-one" not in json.dumps(nextframe)
    await vm2.inbound.put(json.dumps({
        "type": "credentials_ack", "target": "vm-02",
        "username": "operator2", "ok": True,
    }))
    await vm1.inbound.put(None)
    await vm2.inbound.put(None)
    await connection
    await second


@pytest.mark.asyncio
async def test_agent_rejects_mismatched_bootstrap_ack_and_never_dispatches(provision):
    hub = OutboundAgentBroker()
    vm = FakeSocket("A" * 40)
    connected = asyncio.create_task(hub.connect(vm, "vm-01"))
    await asyncio.wait_for(vm.outbound.get(), 1)
    await vm.inbound.put(json.dumps({
        "type": "credentials_ack", "target": "vm-01",
        "username": "wrong", "ok": True,
    }))
    await connected
    assert vm.closed == 4403
    assert not hub.is_connected("vm-01")
    assert "vm-01" not in hub.sessions


@pytest.mark.asyncio
async def test_wrong_bearer_never_receives_password(provision):
    hub = OutboundAgentBroker()
    vm = FakeSocket("invalid")
    await hub.connect(vm, "vm-01")
    assert vm.closed == 4401
    assert vm.outbound.empty()


@pytest.mark.asyncio
async def test_invalid_api_credentials_never_leave_control_plane(provision, monkeypatch):
    monkeypatch.setattr(settings, "VM_AGENT_EXECUTION_CREDENTIALS", {
        "vm-01": {"username": "root", "password": "wrong"},
    })
    hub = OutboundAgentBroker()
    vm = FakeSocket("A" * 40)
    await hub.connect(vm, "vm-01")
    assert vm.closed == 4403
    assert vm.outbound.empty()


def test_agent_accepts_password_only_for_matching_real_execution_identity(provision, monkeypatch):
    monkeypatch.setattr(LocalVMConnector, "execution_identity", classmethod(lambda cls: "opsbot"))
    LocalVMConnector.clear_session_credentials()
    try:
        LocalVMConnector.set_session_credentials("opsbot", "s3cret")
        assert LocalVMConnector._session_sudo_password == "s3cret"
        with pytest.raises(PermissionError, match="username_mismatch"):
            LocalVMConnector.set_session_credentials("someoneelse", "s3cret")
        with pytest.raises(PermissionError, match="password_invalid"):
            LocalVMConnector.set_session_credentials("opsbot", "line\nbreak")
    finally:
        LocalVMConnector.clear_session_credentials()
    assert LocalVMConnector._session_sudo_password is None


@pytest.mark.asyncio
async def test_sudo_fallback_passes_password_on_stdin_and_redacts_output(provision, monkeypatch):
    monkeypatch.setattr(LocalVMConnector, "execution_identity", classmethod(lambda cls: "opsbot"))
    LocalVMConnector.clear_session_credentials()
    LocalVMConnector.set_session_credentials("opsbot", "secret-do-not-echo")
    executor = LocalVMConnector()
    commands = []

    async def fake_run(target, command, *, stdin_data=None):
        commands.append((target, command, stdin_data))
        if len(commands) == 1:
            return {"success": False, "stderr": "sudo: a password is required"}
        return {"success": True, "stdout": "secret-do-not-echo",
                "stderr": "secret-do-not-echo", "exit_code": 0}

    monkeypatch.setattr(executor, "_run", fake_run)
    try:
        result = await executor._sudo(
            "vm-01", "/usr/bin/systemctl restart nginx",
            stdin_data="config-data")
        assert result["stdout"] == "[REDACTED]"
        assert result["stderr"] == "[REDACTED]"
        assert commands[0] == ("vm-01", "sudo -n /usr/bin/systemctl restart nginx", "config-data")
        assert commands[1][1] == "sudo -k -S -p '' /usr/bin/systemctl restart nginx"
        assert commands[1][2] == "secret-do-not-echo\nconfig-data"
        assert "secret-do-not-echo" not in commands[1][1]
    finally:
        LocalVMConnector.clear_session_credentials()


@pytest.mark.asyncio
async def test_sudo_without_bootstrap_credentials_fails_closed(provision, monkeypatch):
    monkeypatch.setattr(LocalVMConnector, "execution_identity", classmethod(lambda cls: "opsbot"))
    LocalVMConnector.clear_session_credentials()
    connector = LocalVMConnector()
    calls = []
    async def fail_sudo(target, command, *, stdin_data=None):
        calls.append(command)
        return {"success": False, "stderr": "sudo: a password is required"}
    monkeypatch.setattr(connector, "_run", fail_sudo)
    result = await connector._sudo("vm-01", "/usr/bin/systemctl restart nginx")
    assert result["error"] == "vm_agent_sudo_credentials_not_provisioned"
    assert len(calls) == 1


@pytest.mark.asyncio
async def test_agent_bootstrap_ack_is_password_free_and_password_cleared_on_disconnect(
        provision, monkeypatch):
    import uuid
    import websockets.asyncio.client as wsclient
    from apps.mcp_server import main as mcp
    from vmmcpagent import outbound

    monkeypatch.setattr(settings, "MCP_SERVER_REQUIRE_AUTH", True)
    monkeypatch.setattr(settings, "VM_AGENT_BEARER_TOKEN", "A" * 40)
    monkeypatch.setattr(settings, "SSH_ENABLED", False)
    monkeypatch.setattr(settings, "VM_AGENT_CA_BUNDLE_PATH", None)
    monkeypatch.setattr(settings, "VM_AGENT_CONTROL_PLANE_WS_URL",
                        "wss://aiops.example.internal/api/v1/vm-agents/connect")
    monkeypatch.setattr(LocalVMConnector, "execution_identity",
                        classmethod(lambda cls: "opsbot"))
    monkeypatch.setattr(LocalVMConnector, "_validate_runtime_security",
                        classmethod(lambda cls: None))
    monkeypatch.setattr(mcp, "_call", AsyncMock(return_value={"success": True}))
    request = json.dumps({
        "type": "execute", "id": str(uuid.uuid4()), "target": "vm-01",
        "tool": "service_status", "arguments": {"target": "vm-01", "service": "nginx"},
        "expires_at": int(time.time()) + 60,
    })
    frames = [
        json.dumps({"type": "credentials", "version": 1, "target": "vm-01",
                    "username": "opsbot", "password": "sudo-secret-one"}),
        request,
    ]
    messages = []
    class Socket:
        async def __aenter__(self): return self
        async def __aexit__(self, *args): return None
        def __aiter__(self):
            async def stream():
                for value in frames: yield value
            return stream()
        async def send(self, data): messages.append(json.loads(data))

    monkeypatch.setattr(wsclient, "connect", lambda *a, **k: Socket())
    async def stop(_delay): raise asyncio.CancelledError()
    monkeypatch.setattr(outbound.asyncio, "sleep", stop)
    with pytest.raises(asyncio.CancelledError):
        await outbound.run_outbound_forever()
    assert messages[0] == {"type": "credentials_ack", "ok": True, "target": "vm-01",
                           "username": "opsbot"}
    assert messages[1]["result"]["success"] is True
    assert "sudo-secret-one" not in json.dumps(messages)
    assert LocalVMConnector._session_sudo_password is None


def test_package_has_safe_execution_username_and_dynamic_systemd_user():
    from pathlib import Path
    folder = Path(__file__).resolve().parents[2] / "vmmcpagent"
    config = (folder / "agent.env.example").read_text()
    installer = (folder / "install.sh").read_text()
    assert "VM_AGENT_EXEC_USERNAME=aiops-agent" in config
    assert "VM_AGENT_EXEC_USERNAME" in installer
    assert "10-execution-user.conf" in installer
    assert 'User=%s' in installer
    assert 'Group=%s' in installer
