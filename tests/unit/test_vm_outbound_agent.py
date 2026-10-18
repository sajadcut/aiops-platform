"""Security and failure-mode contracts for Puppet-style VM agent reverse channels."""
from __future__ import annotations

import asyncio
import json
import time
from unittest.mock import AsyncMock

import pytest
from starlette.websockets import WebSocketDisconnect

from apps.api.vm_agent_broker import OutboundAgentBroker, AgentDisconnected
from domain.contracts.config import settings
from integrations.vm.mcp_client import VMEdgeMCPClient, vm_transport_configured
from vmmcpagent.outbound import broker_url


@pytest.fixture
def pull(monkeypatch):
    monkeypatch.setattr(settings, "VM_EXECUTION_BACKEND", "agent_pull")
    monkeypatch.setattr(settings, "VM_AGENT_TOKENS", {"vm-01": "A" * 40, "vm-02": "B" * 40})
    monkeypatch.setattr(settings, "VM_AGENT_ENDPOINTS", {})
    monkeypatch.setattr(settings, "VM_AGENT_TARGET", "vm-01")
    monkeypatch.setattr(settings, "VM_AGENT_CONTROL_PLANE_WS_URL",
                        "wss://aiops.internal/api/v1/vm-agents/connect")
    monkeypatch.setattr(settings, "VM_AGENT_CA_BUNDLE_PATH", None)


class FakeSocket:
    def __init__(self, token, *, target="vm-01"):
        self.headers = {"authorization": "Bearer " + token}
        self.inbound = asyncio.Queue()
        self.outbound = asyncio.Queue()
        self.accepted = False
        self.closed = None
        self.target = target

    async def accept(self):
        self.accepted = True

    async def close(self, code=1000):
        self.closed = code

    async def receive_text(self):
        raw = await self.inbound.get()
        if raw is None:
            raise WebSocketDisconnect(code=1000)
        return raw

    async def send_text(self, value):
        await self.outbound.put(json.loads(value))

    async def result(self, call, value):
        await self.inbound.put(json.dumps(
            {"type": "result", "id": call["id"], "result": value}
        ))


async def _connected(hub, token="A" * 40, target="vm-01"):
    socket = FakeSocket(token, target=target)
    task = asyncio.create_task(hub.connect(socket, target))
    for _ in range(100):
        if socket.accepted or socket.closed is not None:
            break
        await asyncio.sleep(0.001)
    return socket, task


@pytest.mark.asyncio
async def test_agent_initiates_authenticated_session_and_tool_result(pull):
    hub = OutboundAgentBroker()
    socket, task = await _connected(hub)
    assert socket.accepted
    assert hub.is_connected("vm-01")
    request = asyncio.create_task(hub.dispatch(
        "vm-01", "service_status", {"target": "vm-01", "service": "nginx"},
    ))
    outbound = await asyncio.wait_for(socket.outbound.get(), 1)
    assert outbound["tool"] == "service_status"
    assert outbound["target"] == "vm-01"
    assert outbound["arguments"] == {"target": "vm-01", "service": "nginx"}
    assert outbound["expires_at"] >= time.time()
    await socket.result(outbound, {"success": True, "active_state": "active"})
    assert (await request)["active_state"] == "active"
    await socket.inbound.put(None)
    await task
    assert not hub.is_connected("vm-01")


@pytest.mark.asyncio
async def test_wrong_token_and_unknown_target_never_accept(pull):
    hub = OutboundAgentBroker()
    wrong, task = await _connected(hub, "wrong", "vm-01")
    await task
    assert not wrong.accepted and wrong.closed == 4401
    unknown, task2 = await _connected(hub, "A" * 40, "unregistered")
    await task2
    assert unknown.closed == 4401
    assert hub.sessions == {}


@pytest.mark.asyncio
async def test_duplicate_connection_does_not_take_over_authenticated_host(pull):
    hub = OutboundAgentBroker()
    first, task1 = await _connected(hub)
    second, task2 = await _connected(hub)
    await task2
    assert first.accepted
    assert second.closed == 4409
    await first.inbound.put(None)
    await task1


@pytest.mark.asyncio
async def test_disconnect_while_write_pending_is_unknown_without_retry(pull):
    hub = OutboundAgentBroker()
    socket, task = await _connected(hub)
    request = asyncio.create_task(hub.dispatch(
        "vm-01", "restart_service",
        {"target": "vm-01", "service": "nginx",
         "approval_id": "approval-123", "incident_id": "incident-123"},
    ))
    sent = await asyncio.wait_for(socket.outbound.get(), 1)
    assert sent["tool"] == "restart_service"
    await socket.inbound.put(None)
    await task
    result = await request
    assert result["success"] is False
    assert result["status"] == "execution_outcome_unknown"
    assert result["production_write_performed"] is None
    assert result["requires_independent_reconciliation"] is True
    assert socket.outbound.empty()


@pytest.mark.asyncio
async def test_missing_agent_write_unknown_and_read_fails_closed(pull):
    hub = OutboundAgentBroker()
    result = await hub.dispatch("vm-01", "start_service",
                                {"target": "vm-01", "service": "nginx",
                                 "approval_id": "ap", "incident_id": "inc"})
    assert result["status"] == "agent_not_connected"
    assert result["execution_outcome"] == "NOT_STARTED"
    assert result["production_write_performed"] is False
    with pytest.raises(AgentDisconnected):
        await hub.dispatch("vm-01", "service_status",
                           {"target": "vm-01", "service": "nginx"})
    with pytest.raises(PermissionError):
        await hub.dispatch("vm-03", "service_status",
                           {"target": "vm-03", "service": "nginx"})
    with pytest.raises(PermissionError):
        await hub.dispatch("vm-01", "execute_shell",
                           {"target": "vm-01"})
    with pytest.raises(PermissionError):
        await hub.dispatch("vm-01", "service_status",
                           {"target": "vm-02", "service": "nginx"})


@pytest.mark.asyncio
async def test_client_routes_all_tools_to_broker_without_agent_http(pull, monkeypatch):
    from apps.api import vm_agent_broker

    dispatch = AsyncMock(return_value={"success": True, "active_state": "active"})
    monkeypatch.setattr(vm_agent_broker.broker, "dispatch", dispatch)
    client = VMEdgeMCPClient()
    assert vm_transport_configured() is True
    try:
        state = await client.service_status("vm-01", "nginx")
        assert state["active_state"] == "active"
        await client.restart_service("vm-01", "nginx", "approval1", "incident1")
        assert dispatch.await_count == 2
        assert dispatch.await_args_list[0].args[:2] == ("vm-01", "service_status")
        assert dispatch.await_args_list[1].args[:2] == ("vm-01", "restart_service")
        assert dispatch.await_args_list[1].args[2]["approval_id"] == "approval1"
    finally:
        await client.close()


def test_outbound_wss_url_must_be_verified_fixed_api_path(pull, monkeypatch):
    assert broker_url() == "wss://aiops.internal/api/v1/vm-agents/connect/vm-01"
    for candidate in (
        "ws://aiops.internal/api/v1/vm-agents/connect",
        "wss://user:password@aiops.internal/api/v1/vm-agents/connect",
        "wss://aiops.internal/other-route",
        "wss://aiops.internal/api/v1/vm-agents/connect?token=bad",
    ):
        monkeypatch.setattr(settings, "VM_AGENT_CONTROL_PLANE_WS_URL", candidate)
        with pytest.raises(RuntimeError, match="wss_url_invalid"):
            broker_url()


def test_source_agent_defaults_to_no_inbound_port():
    from pathlib import Path
    root = Path(__file__).resolve().parents[2]
    agent = (root / "vmmcpagent" / "agent.env.example").read_text()
    assert "VM_AGENT_CONNECTION_MODE=outbound" in agent
    assert "VM_AGENT_CONTROL_PLANE_WS_URL=wss://" in agent
    assert "VM_AGENT_TARGET=" in agent
    assert "SSH_ENABLED=False" in agent
    assert "EnvironmentFile=/data/aiopsvmagent/agent.env" in (
        root / "vmmcpagent" / "vmmcpagent.service"
    ).read_text()


@pytest.mark.asyncio
async def test_busy_agent_rejects_second_write_before_send(pull):
    hub = OutboundAgentBroker()
    socket, task = await _connected(hub)
    first = asyncio.create_task(hub.dispatch(
        "vm-01", "service_status", {"target": "vm-01", "service": "nginx"},
    ))
    frame = await asyncio.wait_for(socket.outbound.get(), 1)
    blocked = await hub.dispatch(
        "vm-01", "restart_service", {
            "target": "vm-01", "service": "nginx",
            "approval_id": "approval-123", "incident_id": "incident-123",
        }
    )
    assert blocked["execution_outcome"] == "NOT_STARTED"
    assert blocked["status"] == "agent_queue_full"
    assert socket.outbound.empty(), "A queued write must not be dispatched"
    await socket.result(frame, {"success": True})
    assert (await first)["success"] is True
    await socket.inbound.put(None)
    await task


@pytest.mark.asyncio
async def test_late_or_forged_reply_cannot_satisfy_pending_id(pull):
    hub = OutboundAgentBroker()
    socket, task = await _connected(hub)
    request = asyncio.create_task(hub.dispatch(
        "vm-01", "service_status", {"target": "vm-01", "service": "nginx"},
    ))
    frame = await asyncio.wait_for(socket.outbound.get(), 1)
    await socket.inbound.put(json.dumps({
        "type": "result", "id": "not-" + frame["id"],
        "result": {"success": True, "active_state": "forged"},
    }))
    await asyncio.sleep(0)
    assert not request.done()
    await socket.result(frame, {"success": True, "active_state": "active"})
    assert (await request)["active_state"] == "active"
    await socket.inbound.put(None)
    await task


@pytest.mark.asyncio
async def test_broker_shutdown_closes_sessions_and_unblocks_pending_write(pull):
    hub = OutboundAgentBroker()
    socket, task = await _connected(hub)
    pending = asyncio.create_task(hub.dispatch(
        "vm-01", "start_service", {
            "target": "vm-01", "service": "nginx",
            "approval_id": "approval-123", "incident_id": "incident-123",
        },
    ))
    await asyncio.wait_for(socket.outbound.get(), 1)
    await hub.shutdown()
    assert socket.closed == 1001
    assert (await pending)["status"] == "execution_outcome_unknown"
    await socket.inbound.put(None)
    await task


def test_backend_enum_accepts_pull_but_refuses_arbitrary_mode():
    from domain.contracts.config import Settings
    assert Settings.validate_vm_execution_backend("agent_pull") == "agent_pull"
    with pytest.raises(ValueError):
        Settings.validate_vm_execution_backend("untrusted_backend")


def test_outbound_runner_does_not_bind_uvicorn_listener(pull, monkeypatch):
    from unittest.mock import AsyncMock
    from vmmcpagent import __main__ as entry
    from vmmcpagent import connector, outbound
    import uvicorn

    monkeypatch.setattr(settings, "MCP_SERVER_PROVIDER", "vm_agent")
    monkeypatch.setattr(settings, "VM_AGENT_CONNECTION_MODE", "outbound")
    monkeypatch.setattr(settings, "SSH_ENABLED", False)
    monkeypatch.setattr(settings, "MCP_SERVER_REQUIRE_AUTH", True)
    monkeypatch.setattr(settings, "VM_AGENT_BEARER_TOKEN", "A" * 40)
    monkeypatch.setattr(entry, "configure_agent_environment", lambda: None)
    monkeypatch.setattr(connector, "LocalVMConnector", lambda: object())
    launched = AsyncMock()
    monkeypatch.setattr(outbound, "run_outbound_forever", launched)

    def forbidden_listener(*args, **kwargs):
        raise AssertionError("Outbound Agent must never listen on a VM port")

    monkeypatch.setattr(uvicorn, "run", forbidden_listener)
    entry.main()
    launched.assert_awaited_once()


def test_operator_connection_status_endpoint_requires_permission():
    from apps.api.main import app
    found = [r for r in app.routes
             if getattr(r, "path", "") == "/api/v1/vm-agents/status"]
    assert len(found) == 1
    assert found[0].methods == {"GET"}
    # Route has a required permission dependency rather than leaking
    # registered VM identities or tokens anonymously.
    assert len(found[0].dependencies) > 0


@pytest.mark.asyncio
async def test_outbound_broker_rejects_unsigned_or_unscoped_write(pull):
    hub = OutboundAgentBroker()
    socket, task = await _connected(hub)
    with pytest.raises(PermissionError, match="approval_context_required"):
        await hub.dispatch("vm-01", "restart_service",
                           {"target": "vm-01", "service": "nginx"})
    with pytest.raises(PermissionError):
        await hub.dispatch("vm-01", "config_change_apply", {
            "target": "vm-01", "service": "nginx",
            "claims": {"target": "vm-01"}, "signature": "forged",
        })
    assert socket.outbound.empty()
    await socket.inbound.put(None)
    await task


@pytest.mark.asyncio
async def test_on_host_agent_executes_once_and_rejects_replay_after_reconnect(pull, monkeypatch):
    import uuid
    from apps.mcp_server import main as mcp_server
    from vmmcpagent import connector, outbound
    import websockets.asyncio.client as client_lib

    monkeypatch.setattr(settings, "VM_AGENT_BEARER_TOKEN", "A" * 40)
    monkeypatch.setattr(settings, "SSH_ENABLED", False)
    monkeypatch.setattr(settings, "MCP_SERVER_REQUIRE_AUTH", True)
    monkeypatch.setattr(connector, "LocalVMConnector", lambda: object())
    invoked = AsyncMock(return_value={"success": True, "active_state": "active"})
    monkeypatch.setattr(mcp_server, "_call", invoked)
    request_id = str(uuid.uuid4())
    request = json.dumps({
        "type": "execute", "id": request_id, "tool": "service_status",
        "target": "vm-01",
        "arguments": {"target": "vm-01", "service": "nginx"},
        "expires_at": int(time.time()) + 60,
    })
    sent = []
    connection_args = []

    class AgentSocket:
        def __aiter__(self):
            async def messages():
                yield request
            return messages()

        async def send(self, payload):
            sent.append(json.loads(payload))

    class FakeConnect:
        async def __aenter__(self):
            return AgentSocket()

        async def __aexit__(self, *args):
            return False

    def connect(*args, **kwargs):
        connection_args.append((args, kwargs))
        return FakeConnect()

    monkeypatch.setattr(client_lib, "connect", connect)
    calls = 0
    async def terminate_after_reconnect(seconds):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise asyncio.CancelledError()

    monkeypatch.setattr(outbound.asyncio, "sleep", terminate_after_reconnect)
    with pytest.raises(asyncio.CancelledError):
        await outbound.run_outbound_forever()

    invoked.assert_awaited_once_with(
        "vm_agent", "service_status", {"target": "vm-01", "service": "nginx"}
    )
    assert sent[0]["result"]["success"] is True
    assert sent[1]["result"]["status"] == "duplicate_request_refused"
    assert len(connection_args) == 2
    for args, kwargs in connection_args:
        assert args[0] == "wss://aiops.internal/api/v1/vm-agents/connect/vm-01"
        assert "Bearer " + "A" * 40 == kwargs["additional_headers"]["Authorization"]
        assert "A" * 40 not in args[0]
        assert kwargs["ssl"].verify_mode != 0


def test_pull_mode_approval_signatures_are_per_target_and_host_verifiable(pull, monkeypatch):
    import uuid
    from apps.config_change_authorization import create_claim, verify_claim
    monkeypatch.setattr(settings, "MCP_SERVER_PROVIDER", "elasticsearch")
    claims, signed = create_claim(
        approval_id=str(uuid.uuid4()), incident_id=str(uuid.uuid4()),
        target="vm-01", service="nginx",
        config_file="/etc/nginx/nginx.conf",
        original_sha256="a" * 64, candidate_sha256="b" * 64,
        proposed_change="remove_extra_opening_brace",
    )
    verify_claim(claims, signed, target="vm-01", service="nginx")
    monkeypatch.setattr(settings, "MCP_SERVER_PROVIDER", "vm_agent")
    monkeypatch.setattr(settings, "VM_AGENT_BEARER_TOKEN", "A" * 40)
    verify_claim(claims, signed, target="vm-01", service="nginx")
    monkeypatch.setattr(settings, "VM_AGENT_BEARER_TOKEN", "B" * 40)
    with pytest.raises(PermissionError):
        verify_claim(claims, signed, target="vm-01", service="nginx")
