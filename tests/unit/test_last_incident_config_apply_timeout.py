"""2026-10-16 gfpapi incident: config approval succeeded, but MCP write timed out.

Regression must prove three independent properties:
* remote config guard gets enough time on both SSH and MCP transports,
* config writes are never retried after an ambiguous response,
* an existing systemd auto-restart crash loop is a scoped, NOT implicit, Start.
"""
from __future__ import annotations

from types import SimpleNamespace

import httpx
import pytest

from domain.contracts.config import settings
from integrations.vm.mcp_client import VMEdgeMCPClient
from integrations.vm.ssh_connector import SSHVMConnector
from apps.config_change_auto_queue import _verified_service_start_scope
from integrations.vm.governed_config_change import _start_after_approved_config_apply


def test_only_fixed_config_guard_gets_long_ssh_execution_window(monkeypatch):
    monkeypatch.setattr(settings, "SSH_CONNECT_TIMEOUT", 10)
    connector = SSHVMConnector(timeout=10)
    assert connector._command_deadline_seconds(
        "sudo -n /bin/sh -s -- apply json_syntax /data/app/appsettings.json a b c d"
    ) == 60
    assert connector._command_deadline_seconds(
        "sudo -k -S -p '' /bin/sh -s -- validate json_syntax /data/app/appsettings.json a b c"
    ) == 60
    assert connector._command_deadline_seconds("systemctl start gfpapi") == 15
    assert connector._command_deadline_seconds("sudo -n journalctl -u gfpapi") == 15
    assert connector._command_deadline_seconds("sudo -n /bin/sh -s -- unsafe foo") == 15


@pytest.mark.asyncio
@pytest.mark.parametrize("tool", ["config_change_validate", "config_change_apply"])
async def test_long_config_mcp_has_180_second_per_tool_timeout_and_no_replay(
    monkeypatch, tool
):
    monkeypatch.setattr(settings, "RETRY_MAX_ATTEMPTS", 4)
    monkeypatch.setattr(settings, "MCP_TIMEOUT_SECONDS", 20)
    client = VMEdgeMCPClient(server_url="http://mcp.example/mcp")
    calls = []

    class Transport:
        async def post(self, url, **kwargs):
            calls.append(kwargs)
            raise httpx.ReadTimeout("simulated slow remote configuration guard")

        async def aclose(self):
            pass

    client._client = Transport()
    payload = {
        "jsonrpc": "2.0", "id": 8, "method": "tools/call",
        "params": {"name": tool, "arguments": {"target": "192.0.2.10"}},
    }
    try:
        with pytest.raises(httpx.ReadTimeout):
            await client._post(payload, tool_name=tool)
        assert len(calls) == 1
        assert calls[0]["timeout"] == 180.0
    finally:
        await client.close()


@pytest.mark.asyncio
async def test_auto_restart_crash_loop_can_be_included_in_explicit_start_scope(monkeypatch):
    from apps import config_change_auto_queue as module

    observed = {
        "success": True, "target": "192.0.2.10", "service": "gfpapi",
        "load_state": "loaded", "active_state": "activating",
        "sub_state": "auto-restart", "restart_count": 783, "main_pid": 0,
    }
    class Client:
        async def service_status(self, target, service):
            return observed

    monkeypatch.setattr(module, "VMEdgeMCPClient", Client)
    assert await _verified_service_start_scope(
        target="192.0.2.10", service="gfpapi",
    ) is True
    for delta in (
        {"main_pid": 123},
        {"restart_count": 0},
        {"active_state": "active", "sub_state": "running"},
        {"service": "other"},
        {"target": "192.0.2.99"},
        {"load_state": "not-found"},
        {"success": False},
    ):
        original = dict(observed)
        observed.update(delta)
        assert await _verified_service_start_scope(
            target="192.0.2.10", service="gfpapi",
        ) is False, delta
        observed.clear()
        observed.update(original)


@pytest.mark.asyncio
async def test_signed_postapply_start_works_for_crash_loop_and_checks_systemd():
    calls = []
    class Worker:
        async def service_status(self, target, service):
            calls.append(("status", target, service))
            if len(calls) == 1:
                return {
                    "success": True, "load_state": "loaded",
                    "active_state": "activating", "sub_state": "auto-restart",
                    "main_pid": 0, "restart_count": 783,
                }
            return {
                "success": True, "active_state": "active",
                "sub_state": "running",
            }

        async def start_service(self, target, service):
            calls.append(("start", target, service))
            return {"success": True}

    outcome = await _start_after_approved_config_apply(
        Worker(), target="192.0.2.10", service="gfpapi",
    )
    assert calls == [
        ("status", "192.0.2.10", "gfpapi"),
        ("start", "192.0.2.10", "gfpapi"),
        ("status", "192.0.2.10", "gfpapi"),
    ]
    assert outcome == {
        "attempted": True, "status": "systemd_active",
        "service_recovery_confirmed": True,
    }


def test_auto_prevalidation_timeout_is_not_shorter_than_mcp_config_timeout():
    from pathlib import Path
    root = Path(__file__).resolve().parents[2]
    queue = (root / "apps/config_change_auto_queue.py").read_text()
    api = (root / "apps/api/config_change_execution.py").read_text()
    assert "timeout=200" in queue
    assert "config_apply_transport_timeout_result_unknown" in api
    assert "except httpx.TimeoutException" in api
    assert "The approval has been consumed" in api
