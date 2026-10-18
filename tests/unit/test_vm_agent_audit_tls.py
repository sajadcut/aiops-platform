"""Dual-format VM Agent audit, trace propagation and explicit WSS TLS policy."""
from __future__ import annotations

import json
import logging
import ssl

import pytest

from domain.contracts.config import settings
from domain.contracts.logging import configure_logging
from domain.contracts.context import set_trace_id
from vmmcpagent.audit import safe_frame, audit_frame
from vmmcpagent.outbound import broker_url, outbound_tls_context


@pytest.mark.parametrize("verify", [True, False])
def test_agent_wss_tls_switch_is_explicit_without_disabling_encryption(monkeypatch, verify):
    monkeypatch.setattr(settings, "VM_AGENT_TLS_VERIFY", verify)
    monkeypatch.setattr(settings, "VM_AGENT_CA_BUNDLE_PATH", None)
    monkeypatch.setattr(settings, "VM_AGENT_TARGET", "10.248.16.82")
    monkeypatch.setattr(settings, "VM_AGENT_CONTROL_PLANE_WS_URL",
                        "wss://10.248.41.67/api/v1/vm-agents/connect")
    context = outbound_tls_context()
    assert isinstance(context, ssl.SSLContext)
    assert context.verify_mode == (ssl.CERT_REQUIRED if verify else ssl.CERT_NONE)
    assert context.check_hostname is verify
    assert broker_url().startswith("wss://")
    assert context.minimum_version >= ssl.TLSVersion.TLSv1_2


def test_all_secret_and_candidate_bodies_omitted_from_agent_audit():
    credentials = {
        "type": "credentials", "username": "szendehnam",
        "password": "sensitive-pass-string", "target": "10.248.16.82",
    }
    command = {
        "type": "execute", "id": "8e84a2d4-d7c9-4697-9a61-9591a497747a",
        "target": "10.248.16.82", "tool": "config_change_apply",
        "arguments": {"target": "10.248.16.82", "service": "gfpapi",
                      "candidate": "sensitive-config-text",
                      "signature": "sensitive-signature", "approval_id": "app-09"},
    }
    response = {"type": "result", "id": command["id"],
                "result": {"success": True, "stdout": "database_password=secret-value",
                           "status": "completed", "exit_code": 0}}
    assert "sensitive-pass-string" not in json.dumps(safe_frame(credentials))
    assert "szendehnam" not in json.dumps(safe_frame(credentials))
    assert "sensitive-config-text" not in json.dumps(safe_frame(command))
    assert "sensitive-signature" not in json.dumps(safe_frame(command))
    assert "secret-value" not in json.dumps(safe_frame(response))
    assert safe_frame(command)["tool"] == "config_change_apply"
    assert safe_frame(command)["service"] == "gfpapi"
    assert safe_frame(response)["result_fields"] == ["exit_code", "status", "stdout", "success"]


def test_text_and_json_audit_logs_include_trace_timestamp_level_latency_and_errors(
        monkeypatch, tmp_path):
    import datetime

    changes = {
        "LOG_CONSOLE_ENABLED": False,
        "LOG_TEXT_FILE_ENABLED": True,
        "LOG_JSON_FILE_ENABLED": True,
        "LOG_DIR": str(tmp_path),
        "LOG_TEXT_FILE": "agent-test.log",
        "LOG_JSON_FILE": "agent-test.json.log",
        "LOG_LEVEL": "INFO",
        "LOG_ROTATION_MODE": "size",
        "LOG_MAX_BYTES": 1048576,
        "LOG_BACKUP_COUNT": 1,
        "LOG_UTC": True,
    }
    for key, value in changes.items():
        monkeypatch.setattr(settings, key, value)

    root = logging.getLogger()
    previous_handlers, previous_level = root.handlers[:], root.level
    try:
        configure_logging()
        set_trace_id("trace-agent-123")
        audit_frame("vm_agent_ws_request_received", {
            "type": "credentials", "password": "private-test-password",
            "username": "opsbot", "target": "10.248.16.82",
        }, trace_id="trace-agent-123", byte_count=85)
        audit_frame("vm_agent_ws_response_sent", {
            "type": "result", "id": "trace-agent-123",
            "result": {"success": False, "status": "denied",
                       "stderr": "password=private-test-password"},
        }, trace_id="trace-agent-123", duration_ms=24.65, byte_count=120)
        audit_frame("vm_agent_ws_request_rejected", {
            "type": "execute", "tool": "restart_service",
            "arguments": {"password": "private-test-password"},
        }, trace_id="trace-agent-123", error_type="policy_rejected")
    finally:
        set_trace_id("")
        for handler in root.handlers:
            handler.flush()
            handler.close()
        root.handlers = previous_handlers
        root.setLevel(previous_level)

    json_file = tmp_path / "agent-test.json.log"
    text_file = tmp_path / "agent-test.log"
    assert json_file.exists() and text_file.exists()
    records = [json.loads(line) for line in json_file.read_text().splitlines()]
    assert len(records) == 3
    assert all(r["trace_id"] == "trace-agent-123" for r in records)
    assert all(r["level"] in {"info", "warning"} for r in records)
    assert all(datetime.datetime.fromisoformat(r["timestamp"].replace("Z", "+00:00")) for r in records)
    assert records[1]["response_time_ms"] == pytest.approx(24.65)
    assert records[2]["error_type"] == "policy_rejected"
    assert records[0]["event"] == "vm_agent_ws_request_received"
    assert records[1]["event"] == "vm_agent_ws_response_sent"
    text_content = text_file.read_text()
    serialized = json_file.read_text() + text_content
    assert "private-test-password" not in serialized
    assert "trace-agent-123" in serialized
    assert "24.65" in serialized
    assert "policy_rejected" in serialized


def test_vm_agent_configuration_explicit_dual_logs_and_tls_default():
    from pathlib import Path
    template = (Path(__file__).resolve().parents[2] / "vmmcpagent" / "agent.env.example").read_text()
    expected = (
        "VM_AGENT_TLS_VERIFY=True",
        "LOG_TEXT_FILE_ENABLED=True",
        "LOG_JSON_FILE_ENABLED=True",
        "LOG_DIR=/data/aiopsvmagent/logs",
        "LOG_TEXT_FILE=aiopsvmagent.log",
        "LOG_JSON_FILE=aiopsvmagent.json.log",
        "LOG_LEVEL=INFO",
        "LOG_UTC=True",
    )
    for line in expected:
        assert line in template


@pytest.mark.asyncio
async def test_real_agent_websocket_loop_audits_each_request_and_response(monkeypatch):
    import asyncio
    import time
    import uuid
    import websockets.asyncio.client as ws_client
    from unittest.mock import AsyncMock
    from apps.mcp_server import main as mcp
    from vmmcpagent import connector, outbound

    monkeypatch.setattr(settings, "APP_ENV", "test")
    monkeypatch.setattr(settings, "VM_AGENT_TARGET", "vm-01")
    monkeypatch.setattr(settings, "VM_AGENT_CONTROL_PLANE_WS_URL",
                        "wss://aiops.example.internal/api/v1/vm-agents/connect")
    monkeypatch.setattr(settings, "VM_AGENT_BEARER_TOKEN", "A" * 40)
    monkeypatch.setattr(settings, "SSH_ENABLED", False)
    monkeypatch.setattr(settings, "MCP_SERVER_REQUIRE_AUTH", True)
    monkeypatch.setattr(settings, "VM_AGENT_TLS_VERIFY", True)
    monkeypatch.setattr(settings, "VM_AGENT_CA_BUNDLE_PATH", None)
    monkeypatch.setattr(connector, "LocalVMConnector", lambda: object())
    invoked = AsyncMock(return_value={
        "success": True, "stdout": "db_password=topsecret",
        "active_state": "active"})
    monkeypatch.setattr(mcp, "_call", invoked)
    call_id = str(uuid.uuid4())
    frame = json.dumps({
        "type": "execute", "id": call_id, "target": "vm-01",
        "tool": "service_status",
        "arguments": {"target": "vm-01", "service": "gfpapi", "secret": "topsecret"},
        "expires_at": int(time.time()) + 60,
    })
    events, response_frames = [], []

    class Socket:
        async def __aenter__(self): return self
        async def __aexit__(self, *args): return None
        def __aiter__(self):
            async def frames():
                yield frame
            return frames()
        async def send(self, payload):
            response_frames.append(json.loads(payload))

    monkeypatch.setattr(ws_client, "connect", lambda *a, **k: Socket())

    def safe_audit(event, data, **kwargs):
        events.append({"event": event, "safe": safe_frame(data), **kwargs})

    monkeypatch.setattr(outbound, "audit_frame", safe_audit)
    async def stop(_delay):
        raise asyncio.CancelledError()
    monkeypatch.setattr(outbound.asyncio, "sleep", stop)
    with pytest.raises(asyncio.CancelledError):
        await outbound.run_outbound_forever()
    invoked.assert_awaited_once()
    assert response_frames[0]["result"]["active_state"] == "active"
    req = next(x for x in events if x["event"] == "vm_agent_ws_request_received")
    resp = next(x for x in events if x["event"] == "vm_agent_ws_response_sent")
    assert req["trace_id"] == call_id
    assert resp["trace_id"] == call_id
    assert resp["duration_ms"] >= 0
    assert req["safe"]["service"] == "gfpapi"
    assert req["safe"]["argument_fields"] == ["secret", "service", "target"]
    assert "topsecret" not in json.dumps(events)
