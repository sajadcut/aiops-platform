"""Lab-only WS:80 must authenticate both peers and encrypt sudo credentials."""
from __future__ import annotations

import asyncio
import json

import pytest

from domain.contracts.config import settings
from integrations.vm.agent_ws_test_cipher import (
    FrameCipher, SecureChannelError, _key, secure_agent, secure_server,
)
from vmmcpagent.outbound import broker_url


class Pair:
    def __init__(self):
        self.to_agent = asyncio.Queue()
        self.to_api = asyncio.Queue()
        self.transmitted_api = []
        self.transmitted_agent = []

    class API:
        def __init__(self, pair):
            self.pair = pair

        async def send_text(self, data):
            self.pair.transmitted_api.append(data)
            await self.pair.to_agent.put(data)

        async def receive_text(self):
            return await self.pair.to_api.get()

        async def close(self, **kwargs):
            pass

    class Agent:
        def __init__(self, pair):
            self.pair = pair

        async def send(self, data):
            self.pair.transmitted_agent.append(data)
            await self.pair.to_api.put(data)

        async def recv(self):
            return await self.pair.to_agent.get()

        async def close(self, **kwargs):
            pass

    def sockets(self):
        return self.API(self), self.Agent(self)


@pytest.mark.asyncio
async def test_mutual_auth_seals_password_requests_responses_and_rejects_replay():
    pair = Pair()
    api, agent = pair.sockets()
    key = "d9" * 32
    target = "10.248.16.82"
    server_future = asyncio.create_task(secure_server(api, target, key))
    protected_agent = await asyncio.wait_for(secure_agent(agent, target, key), 1)
    protected_api = await asyncio.wait_for(server_future, 1)
    credentials = json.dumps({"type": "credentials", "target": target,
                              "password": "do-not-log-this-password"})
    await protected_api.send_text(credentials)
    received = await protected_agent.socket.recv()
    assert "do-not-log-this-password" not in received
    assert json.loads(received)["type"] == "sealed"
    assert protected_agent.cipher.decrypt(received) == credentials
    with pytest.raises(SecureChannelError, match="replay"):
        protected_agent.cipher.decrypt(received)
    await protected_agent.send(json.dumps({"type": "credentials_ack", "ok": True}))
    ack_frame = await protected_api.socket.receive_text()
    assert "credentials_ack" not in ack_frame
    assert json.loads(protected_api.cipher.decrypt(ack_frame))["ok"] is True
    assert "do-not-log-this-password" not in "".join(pair.transmitted_api)
    assert key not in "".join(pair.transmitted_api + pair.transmitted_agent)


@pytest.mark.asyncio
async def test_mutual_auth_blocks_wrong_agent_key_before_credentials():
    pair = Pair()
    api, agent = pair.sockets()
    server_future = asyncio.create_task(secure_server(api, "10.248.16.82", "a1" * 32))
    agent_future = asyncio.create_task(secure_agent(agent, "10.248.16.82", "b2" * 32))
    with pytest.raises(SecureChannelError, match="client_authentication_failed"):
        await asyncio.wait_for(server_future, 1)
    agent_future.cancel()
    with pytest.raises(asyncio.CancelledError):
        await agent_future
    assert len(pair.transmitted_api) == 1, "No sudo password before mutual authentication"


@pytest.mark.asyncio
async def test_frame_tampering_and_out_of_order_fail_closed():
    pair = Pair()
    api, agent = pair.sockets()
    sf = asyncio.create_task(secure_server(api, "vm-01", "c3" * 32))
    client = await asyncio.wait_for(secure_agent(agent, "vm-01", "c3" * 32), 1)
    server = await sf
    await server.send_text('{"type":"execute","tool":"service_status"}')
    raw = await agent.recv()
    corrupted = json.loads(raw)
    corrupted["data"] = ("A" if corrupted["data"][0] != "A" else "B") + corrupted["data"][1:]
    with pytest.raises(SecureChannelError, match="authentication_failed"):
        client.cipher.decrypt(json.dumps(corrupted))
    with pytest.raises(SecureChannelError, match="replay_or_out_of_order"):
        client.cipher.decrypt(json.dumps({**json.loads(raw), "seq": 5}))
    assert "service_status" in client.cipher.decrypt(raw)


def test_unencrypted_ws80_is_only_allowed_with_explicit_test_psk_mode(monkeypatch):
    monkeypatch.setattr(settings, "VM_AGENT_CONTROL_PLANE_WS_URL",
                        "ws://10.248.41.67:80/api/v1/vm-agents/connect")
    monkeypatch.setattr(settings, "VM_AGENT_TARGET", "10.248.16.82")
    monkeypatch.setattr(settings, "VM_AGENT_WS_TEST_MODE", False)
    monkeypatch.setattr(settings, "APP_ENV", "test")
    with pytest.raises(RuntimeError, match="wss_url_invalid"):
        broker_url()
    monkeypatch.setattr(settings, "VM_AGENT_WS_TEST_MODE", True)
    assert broker_url() == "ws://10.248.41.67:80/api/v1/vm-agents/connect/10.248.16.82"
    monkeypatch.setattr(settings, "APP_ENV", "production")
    with pytest.raises(RuntimeError, match="wss_url_invalid"):
        broker_url()
    for bad in ("ws://user:pass@10.248.41.67:80/api/v1/vm-agents/connect",
                "ws://10.248.41.67:80/wrong", "ws://10.248.41.67:80/api/v1/vm-agents/connect?key=abc"):
        monkeypatch.setattr(settings, "VM_AGENT_CONTROL_PLANE_WS_URL", bad)
        with pytest.raises(RuntimeError):
            broker_url()


def test_test_psk_requires_hex_32_bytes():
    for bad in (None, "", "aa", "zz" * 32, "aa" * 31, "aa" * 33):
        with pytest.raises(SecureChannelError):
            _key(bad)
