"""Regressions for outbound VM agent operational readiness and write ambiguity."""
from __future__ import annotations

import asyncio
import json
import time
from unittest.mock import AsyncMock

import pytest

from apps.api.health import _external_required_ready
from domain.contracts.config import settings
from vmmcpagent.outbound import _execution_failure


def test_pull_agent_connection_cannot_deadlock_api_readiness(monkeypatch):
    monkeypatch.setattr(settings, "APP_ENV", "production")
    monkeypatch.setattr(settings, "VM_AGENT_TOKENS", {"vm-01": "A" * 40})
    monkeypatch.setattr(settings, "VM_AGENT_ENDPOINTS", {})
    monkeypatch.setattr(settings, "VM_EXECUTION_BACKEND", "agent_pull")
    monkeypatch.setattr(settings, "KUBERNETES_MCP_URL", None)
    monkeypatch.setattr(settings, "JENKINS_MCP_URL", None)
    external = {
        "zabbix_mcp": {"healthy": True},
        "elasticsearch_mcp": {"healthy": True},
        "prometheus_mcp": {"healthy": True},
        "cognia": {"healthy": True},
        "vm_mcp": {"healthy": False},
    }
    assert _external_required_ready(external) is True
    # Inbound modes retain the existing explicit dependency gate.
    monkeypatch.setattr(settings, "VM_EXECUTION_BACKEND", "agent")
    monkeypatch.setattr(settings, "VM_AGENT_ENDPOINTS",
                        {"vm-01": "https://vm01.example.internal/mcp"})
    assert _external_required_ready(external) is False
    monkeypatch.setattr(settings, "VM_EXECUTION_BACKEND", "ssh")
    monkeypatch.setattr(settings, "VM_MCP_URL", "http://127.0.0.1:9105/mcp")
    assert _external_required_ready(external) is False


@pytest.mark.parametrize("tool", [
    "start_service", "restart_service", "reload_service", "config_change_apply",
])
def test_write_failure_after_dispatch_never_claims_no_write(tool):
    for cause in ("agent_execution_failed", "duplicate_request_refused",
                  "agent_result_too_large"):
        report = _execution_failure(tool, cause, sent_to_executor=True)
        assert report["success"] is False
        assert report["status"] == "execution_outcome_unknown"
        assert report["execution_outcome"] == "UNKNOWN"
        assert report["production_write_performed"] is None
        assert report["requires_independent_reconciliation"] is True


@pytest.mark.parametrize("tool", [
    "start_service", "restart_service", "reload_service", "config_change_apply",
])
def test_write_expiry_before_dispatch_is_not_started(tool):
    report = _execution_failure(tool, "request_expired", sent_to_executor=False)
    assert report["status"] == "request_expired"
    assert report["execution_outcome"] == "NOT_STARTED"
    assert report["production_write_performed"] is False


@pytest.mark.asyncio
async def test_agent_exception_during_restart_returns_unknown_to_control_plane(monkeypatch):
    import uuid
    import websockets.asyncio.client as client_lib
    from apps.mcp_server import main as mcp
    from vmmcpagent import connector, outbound

    monkeypatch.setattr(settings, "VM_AGENT_TARGET", "vm-01")
    monkeypatch.setattr(settings, "VM_AGENT_CONTROL_PLANE_WS_URL",
                        "wss://aiops.example.internal/api/v1/vm-agents/connect")
    monkeypatch.setattr(settings, "VM_AGENT_BEARER_TOKEN", "A" * 40)
    monkeypatch.setattr(settings, "MCP_SERVER_REQUIRE_AUTH", True)
    monkeypatch.setattr(settings, "SSH_ENABLED", False)
    monkeypatch.setattr(settings, "VM_AGENT_CA_BUNDLE_PATH", None)
    monkeypatch.setattr(connector, "LocalVMConnector", lambda: object())
    monkeypatch.setattr(mcp, "_call", AsyncMock(side_effect=RuntimeError("lost sudo result")))

    command = json.dumps({
        "type": "execute", "id": str(uuid.uuid4()),
        "target": "vm-01", "tool": "restart_service",
        "arguments": {"target": "vm-01", "service": "nginx",
                      "approval_id": "approved", "incident_id": "incident"},
        "expires_at": int(time.time()) + 60,
    })
    sent = []

    class FakeConnection:
        async def __aenter__(self): return self
        async def __aexit__(self, *args): return None
        def __aiter__(self):
            async def frames():
                yield command
            return frames()
        async def send(self, payload): sent.append(json.loads(payload))

    monkeypatch.setattr(client_lib, "connect", lambda *a, **kw: FakeConnection())

    async def end_loop(_delay):
        raise asyncio.CancelledError()

    monkeypatch.setattr(outbound.asyncio, "sleep", end_loop)
    with pytest.raises(asyncio.CancelledError):
        await outbound.run_outbound_forever()
    assert len(sent) == 1
    assert sent[0]["result"]["execution_outcome"] == "UNKNOWN"
    assert sent[0]["result"]["production_write_performed"] is None


def test_agent_pull_signing_readiness_uses_per_host_keys_not_fleet_bearer(monkeypatch):
    from apps.config_change_authorization import config_signing_ready
    from apps.api.config_change_review import _review_progress

    monkeypatch.setattr(settings, "MCP_SERVER_PROVIDER", "elasticsearch")
    monkeypatch.setattr(settings, "VM_EXECUTION_BACKEND", "agent_pull")
    monkeypatch.setattr(settings, "MCP_BEARER_TOKEN", "F" * 48)
    monkeypatch.setattr(settings, "VM_AGENT_TOKENS", {})
    assert config_signing_ready() is False
    monkeypatch.setattr(settings, "VM_AGENT_TOKENS",
                        {"vm01": "K" * 40, "vm02": "weak"})
    assert config_signing_ready() is False
    monkeypatch.setattr(settings, "VM_AGENT_TOKENS",
                        {"vm01": "K" * 40, "vm02": "L" * 40})
    assert config_signing_ready() is True

    report = _review_progress(
        status="approved", decision="request_change_approval",
        proposal={"service": "nginx", "config_file": "/etc/nginx/nginx.conf",
                  "validation_status": "UNVERIFIED"},
        approval={"approval_id": "11111111-1111-4111-8111-111111111111",
                  "status": "approved", "metadata": {"isolated_validation": True}},
    )
    prereqs = report["execution_prerequisites"]
    assert prereqs["signing_source"] == "VM_AGENT_TOKENS"
    assert prereqs["api_signing_key"] == "derived_from_agent_target_tokens"
    assert prereqs["execution_ready"] is False
    assert "K" * 40 not in repr(prereqs)
    monkeypatch.setattr(settings, "VM_AGENT_TOKENS", {"vm01": "weak"})
    blocked = _review_progress(
        status="approved", decision="request_change_approval",
        proposal={"service": "nginx", "config_file": "/etc/nginx/nginx.conf",
                  "validation_status": "UNVERIFIED"},
        approval={"approval_id": "11111111-1111-4111-8111-111111111111",
                  "status": "approved", "metadata": {"isolated_validation": True}},
    )
    assert blocked["execution_prerequisites"]["api_signing_key"] == "missing_or_weak_agent_target_token"


@pytest.mark.asyncio
async def test_replay_cache_never_evicts_unexpired_write_ids(monkeypatch):
    import uuid
    import websockets.asyncio.client as client_lib
    from apps.mcp_server import main as mcp
    from vmmcpagent import connector, outbound

    monkeypatch.setattr(settings, "VM_AGENT_TARGET", "vm-01")
    monkeypatch.setattr(settings, "VM_AGENT_CONTROL_PLANE_WS_URL",
                        "wss://aiops.example.internal/api/v1/vm-agents/connect")
    monkeypatch.setattr(settings, "VM_AGENT_BEARER_TOKEN", "A" * 40)
    monkeypatch.setattr(settings, "MCP_SERVER_REQUIRE_AUTH", True)
    monkeypatch.setattr(settings, "SSH_ENABLED", False)
    monkeypatch.setattr(settings, "VM_AGENT_CA_BUNDLE_PATH", None)
    monkeypatch.setattr(connector, "LocalVMConnector", lambda: object())
    monkeypatch.setattr(outbound, "_MAX_REPLAY_ENTRIES", 1)
    invoked = AsyncMock(return_value={"success": True})
    monkeypatch.setattr(mcp, "_call", invoked)

    expiry = int(time.time()) + 60
    ids = [str(uuid.uuid4()), str(uuid.uuid4())]
    def command(ident):
        return json.dumps({
            "type": "execute", "id": ident, "target": "vm-01",
            "tool": "restart_service",
            "arguments": {"target": "vm-01", "service": "nginx",
                          "approval_id": "approval-123", "incident_id": "incident-123"},
            "expires_at": expiry,
        })
    sent = []

    class FakeConnection:
        async def __aenter__(self): return self
        async def __aexit__(self, *args): return None
        def __aiter__(self):
            async def frames():
                yield command(ids[0])
                yield command(ids[1])
                yield command(ids[0])  # still live; replay must be refused
            return frames()
        async def send(self, payload): sent.append(json.loads(payload))

    monkeypatch.setattr(client_lib, "connect", lambda *a, **kw: FakeConnection())
    async def end_loop(_delay): raise asyncio.CancelledError()
    monkeypatch.setattr(outbound.asyncio, "sleep", end_loop)
    with pytest.raises(asyncio.CancelledError):
        await outbound.run_outbound_forever()

    assert invoked.await_count == 1
    assert sent[0]["result"]["success"] is True
    assert sent[1]["result"]["execution_outcome"] == "NOT_STARTED"
    assert sent[1]["result"]["status"] == "request_replay_guard_full"
    assert sent[2]["result"]["execution_outcome"] == "UNKNOWN"
    assert sent[2]["result"]["reason"] == "duplicate_request_refused"


@pytest.mark.asyncio
async def test_vm_relative_monotonic_lease_ignores_wall_clock_skew(monkeypatch):
    """v2 works when the VM wall clock is far from the API wall clock."""
    import uuid
    import websockets.asyncio.client as wsclient
    from apps.mcp_server import main as mcp
    from vmmcpagent import connector, outbound

    monkeypatch.setattr(settings, "VM_AGENT_TARGET", "vm-01")
    monkeypatch.setattr(settings, "VM_AGENT_CONTROL_PLANE_WS_URL",
                        "wss://aiops.example.internal/api/v1/vm-agents/connect")
    monkeypatch.setattr(settings, "VM_AGENT_BEARER_TOKEN", "A" * 40)
    monkeypatch.setattr(settings, "MCP_SERVER_REQUIRE_AUTH", True)
    monkeypatch.setattr(settings, "SSH_ENABLED", False)
    monkeypatch.setattr(settings, "VM_AGENT_CA_BUNDLE_PATH", None)
    monkeypatch.setattr(connector, "LocalVMConnector", lambda: object())
    # The old wall-clock protocol rejects this deliberately extreme skew.
    monkeypatch.setattr(outbound.time, "time", lambda: 1_000_000)
    monkeypatch.setattr(outbound, "_monotonic_time", lambda: 12345.0)
    invoked = AsyncMock(return_value={"success": True, "active_state": "active"})
    monkeypatch.setattr(mcp, "_call", invoked)
    ident = str(uuid.uuid4())
    execute = json.dumps({
        "type": "execute", "id": ident, "target": "vm-01",
        "tool": "restart_service",
        "arguments": {"target": "vm-01", "service": "nginx",
                      "approval_id": "approved", "incident_id": "incident"},
        "ttl_seconds": 60,
    })
    sent = []

    class FakeConnection:
        async def __aenter__(self): return self
        async def __aexit__(self, *args): return None
        def __aiter__(self):
            async def frames():
                yield execute
                assert invoked.await_count == 0, "Write ran before broker commit"
                yield json.dumps({"type": "execute_commit", "id": ident})
            return frames()
        async def send(self, payload): sent.append(json.loads(payload))

    monkeypatch.setattr(wsclient, "connect", lambda *a, **kw: FakeConnection())
    async def stop(_delay): raise asyncio.CancelledError()
    monkeypatch.setattr(outbound.asyncio, "sleep", stop)
    with pytest.raises(asyncio.CancelledError):
        await outbound.run_outbound_forever()
    assert sent[0] == {"type": "execute_ready", "id": ident}
    assert sent[1]["type"] == "result"
    assert sent[1]["result"]["success"] is True
    invoked.assert_awaited_once()


@pytest.mark.asyncio
async def test_vm_relative_write_rejects_expired_commit_without_execution(monkeypatch):
    import uuid
    import websockets.asyncio.client as wsclient
    from apps.mcp_server import main as mcp
    from vmmcpagent import connector, outbound

    monkeypatch.setattr(settings, "VM_AGENT_TARGET", "vm-01")
    monkeypatch.setattr(settings, "VM_AGENT_CONTROL_PLANE_WS_URL",
                        "wss://aiops.example.internal/api/v1/vm-agents/connect")
    monkeypatch.setattr(settings, "VM_AGENT_BEARER_TOKEN", "A" * 40)
    monkeypatch.setattr(settings, "MCP_SERVER_REQUIRE_AUTH", True)
    monkeypatch.setattr(settings, "SSH_ENABLED", False)
    monkeypatch.setattr(settings, "VM_AGENT_CA_BUNDLE_PATH", None)
    monkeypatch.setattr(connector, "LocalVMConnector", lambda: object())
    mono = iter([100.0, 102.0])
    monkeypatch.setattr(outbound, "_monotonic_time", lambda: next(mono))
    invoked = AsyncMock(return_value={"success": True})
    monkeypatch.setattr(mcp, "_call", invoked)
    ident = str(uuid.uuid4())
    sent = []

    class FakeConnection:
        async def __aenter__(self): return self
        async def __aexit__(self, *args): return None
        def __aiter__(self):
            async def frames():
                yield json.dumps({
                    "type": "execute", "id": ident, "target": "vm-01",
                    "tool": "restart_service",
                    "arguments": {"target": "vm-01", "service": "nginx"},
                    "ttl_seconds": 1,
                })
                yield json.dumps({"type": "execute_commit", "id": ident})
            return frames()
        async def send(self, payload): sent.append(json.loads(payload))
    monkeypatch.setattr(wsclient, "connect", lambda *a, **kw: FakeConnection())
    async def stop(_delay): raise asyncio.CancelledError()
    monkeypatch.setattr(outbound.asyncio, "sleep", stop)
    with pytest.raises(asyncio.CancelledError):
        await outbound.run_outbound_forever()
    assert sent[0]["type"] == "execute_ready"
    assert sent[1]["result"]["execution_outcome"] == "NOT_STARTED"
    assert sent[1]["result"]["status"] == "request_expired"
    invoked.assert_not_awaited()


def test_relative_outbound_config_apply_rebases_only_valid_original_hmac(monkeypatch):
    """VM is 4m37s ahead: its root guard still receives 55s VM-local proof."""
    from types import SimpleNamespace
    import apps.config_change_authorization as auth
    from domain.contracts.config import settings

    monkeypatch.setattr(settings, "MCP_SERVER_PROVIDER", "vm_agent")
    monkeypatch.setattr(settings, "VM_AGENT_BEARER_TOKEN", "A" * 40)
    api_now, vm_now = 1_000_000, 1_000_277
    monkeypatch.setattr(auth, "time", SimpleNamespace(time=lambda: api_now))
    claims, signed = auth.create_claim(
        approval_id="approval-id", incident_id="incident-id",
        target="vm-01", service="nginx",
        config_file="/etc/nginx/nginx.conf",
        original_sha256="a" * 64, candidate_sha256="b" * 64,
        proposed_change="remove_extra_opening_brace",
    )
    monkeypatch.setattr(auth, "time", SimpleNamespace(time=lambda: vm_now))
    with pytest.raises(PermissionError, match="config_execution_claim_expired"):
        auth.verify_claim(claims, signed, target="vm-01", service="nginx")
    local, signature = auth.rebase_authenticated_outbound_claim(
        claims, signed, target="vm-01", service="nginx",
        remaining_seconds=30.2,
    )
    assert local["expires"] == vm_now + 31
    assert local["approval_id"] == claims["approval_id"]
    assert local["candidate_sha256"] == claims["candidate_sha256"]
    auth.verify_claim(local, signature, target="vm-01", service="nginx")
    assert signature != signed
    with pytest.raises(PermissionError, match="config_execution_claim_signature_invalid"):
        auth.rebase_authenticated_outbound_claim(
            {**claims, "candidate_sha256": "c" * 64}, signed,
            target="vm-01", service="nginx", remaining_seconds=30,
        )
    with pytest.raises(PermissionError, match="config_execution_lease_expired"):
        auth.rebase_authenticated_outbound_claim(
            claims, signed, target="vm-01", service="nginx",
            remaining_seconds=0,
        )
    monkeypatch.setattr(auth, "time", SimpleNamespace(time=lambda: vm_now + 32))
    with pytest.raises(PermissionError, match="config_execution_claim_expired"):
        auth.verify_claim(local, signature, target="vm-01", service="nginx")


@pytest.mark.asyncio
@pytest.mark.parametrize("tampered", [False, True])
async def test_agent_config_apply_commit_localizes_signed_expiry_only_when_authentic(
    monkeypatch, tampered,
):
    """Exercise actual WebSocket execute -> ready -> commit -> MCP boundary."""
    import uuid
    from types import SimpleNamespace
    import websockets.asyncio.client as wsclient
    import apps.config_change_authorization as auth
    from apps.mcp_server import main as mcp
    from vmmcpagent import connector, outbound

    monkeypatch.setattr(settings, "APP_ENV", "test")
    monkeypatch.setattr(settings, "MCP_SERVER_PROVIDER", "vm_agent")
    monkeypatch.setattr(settings, "VM_AGENT_TARGET", "vm-01")
    monkeypatch.setattr(settings, "VM_AGENT_CONTROL_PLANE_WS_URL",
                        "wss://aiops.example.internal/api/v1/vm-agents/connect")
    monkeypatch.setattr(settings, "VM_AGENT_BEARER_TOKEN", "A" * 40)
    monkeypatch.setattr(settings, "MCP_SERVER_REQUIRE_AUTH", True)
    monkeypatch.setattr(settings, "SSH_ENABLED", False)
    monkeypatch.setattr(settings, "VM_AGENT_CA_BUNDLE_PATH", None)
    monkeypatch.setattr(connector, "LocalVMConnector", lambda: object())
    api_time, vm_time = 1_000_000, 1_000_277
    monkeypatch.setattr(auth, "time", SimpleNamespace(time=lambda: api_time))
    claims, signature = auth.create_claim(
        approval_id="approval-123", incident_id="incident-123",
        target="vm-01", service="nginx",
        config_file="/etc/nginx/nginx.conf",
        original_sha256="a" * 64, candidate_sha256="b" * 64,
        proposed_change="remove_extra_opening_brace",
    )
    monkeypatch.setattr(auth, "time", SimpleNamespace(time=lambda: vm_time))
    if tampered:
        claims = {**claims, "candidate_sha256": "c" * 64}
    monkeypatch.setattr(outbound, "_monotonic_time", lambda: 100.0)

    async def guarded_call(provider, tool, args):
        assert provider == "vm_agent"
        assert tool == "config_change_apply"
        assert args["claims"]["approval_id"] == "approval-123"
        assert args["claims"]["candidate_sha256"] == "b" * 64
        assert vm_time < args["claims"]["expires"] <= vm_time + 55
        auth.verify_claim(args["claims"], args["signature"],
                          target="vm-01", service="nginx")
        return {"success": True, "status": "applied_verified",
                "production_write_performed": True}
    invoked = AsyncMock(side_effect=guarded_call)
    monkeypatch.setattr(mcp, "_call", invoked)

    ident = str(uuid.uuid4())
    ready = []
    class FakeConnection:
        async def __aenter__(self): return self
        async def __aexit__(self, *args): return None
        def __aiter__(self):
            async def frames():
                yield json.dumps({
                    "type": "execute", "id": ident, "target": "vm-01",
                    "tool": "config_change_apply",
                    "arguments": {"target": "vm-01", "service": "nginx",
                                  "claims": claims, "signature": signature},
                    "ttl_seconds": 50,
                })
                assert not invoked.await_count
                yield json.dumps({"type": "execute_commit", "id": ident})
            return frames()
        async def send(self, payload): ready.append(json.loads(payload))
    monkeypatch.setattr(wsclient, "connect", lambda *a, **kw: FakeConnection())
    async def stop(_delay): raise asyncio.CancelledError()
    monkeypatch.setattr(outbound.asyncio, "sleep", stop)
    with pytest.raises(asyncio.CancelledError):
        await outbound.run_outbound_forever()
    assert ready[0] == {"type": "execute_ready", "id": ident}
    if tampered:
        invoked.assert_not_awaited()
        assert ready[1]["result"]["execution_outcome"] == "NOT_STARTED"
        assert ready[1]["result"]["production_write_performed"] is False
        assert ready[1]["result"]["status"] == "config_execution_claim_signature_invalid"
    else:
        invoked.assert_awaited_once()
        assert ready[1]["result"]["success"] is True
