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
