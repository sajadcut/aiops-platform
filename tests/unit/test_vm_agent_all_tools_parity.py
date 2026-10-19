"""Exhaustive dispatch parity between SSH-backed VM MCP and installed VM Agent.

This suite asserts that EVERY exported VM MCP tool (not a hand-picked sample)
dispatches to the same connector method, with identical argument projections
and result shapes. It does not replace real-host acceptance for sudo, systemd,
vendor validators, config candidate storage or rollback.
"""
from __future__ import annotations

import inspect
from unittest.mock import AsyncMock

import pytest

from apps.mcp_server import main as server
from integrations.vm.ssh_connector import SSHVMConnector
from integrations.vm.local_agent_connector import LocalVMConnector
from integrations.vm.mcp_client import VMEdgeMCPClient

SAMPLE = {
    "target": "vm-parity-01",
    "service": "nginx",
    "process": "nginx",
    "host": "127.0.0.1",
    "port": 443,
    "hostname": "localhost",
    "destination": "127.0.0.1",
    "limit": 25,
    "query": "nginx",
    "config_file": "/etc/nginx/nginx.conf",
    "original_sha256": "a" * 64,
    "candidate_sha256": "b" * 64,
    "proposed_change": "remove_extra_opening_brace",
    "approval_id": "a-123",
    "incident_id": "i-123",
    "signature": "f" * 64,
    "claims": {
        "config_file": "/etc/nginx/nginx.conf",
        "original_sha256": "a" * 64,
        "candidate_sha256": "b" * 64,
        "proposed_change": "remove_extra_opening_brace",
    },
}


@pytest.mark.parametrize("name", sorted(VMEdgeMCPClient.READ_TOOLS | VMEdgeMCPClient.WRITE_TOOLS))
@pytest.mark.asyncio
async def test_every_vm_tool_dispatch_is_identical_for_ssh_and_local_agent(name, monkeypatch):
    """The registered surface, parameter routing, and output parity is exhaustive."""
    assert name in server._TOOL_SCHEMAS["vm"]
    assert name in server._TOOL_SCHEMAS["vm_agent"]
    schema = server._TOOL_SCHEMAS["vm"][name]["inputSchema"]
    args = {key: SAMPLE[key] for key in set(schema.get("required", [])) | set(SAMPLE) if key in schema.get("properties", {})}
    args["target"] = SAMPLE["target"]
    if name == "config_change_apply":
        args.update({"claims": SAMPLE["claims"], "signature": SAMPLE["signature"]})
    recorded = []

    class SpyConnector:
        def __init__(self, mode):
            self.mode = mode
        def _validate_target(self, target):
            assert target == SAMPLE["target"]
        def _validate_service(self, service):
            assert service == SAMPLE["service"]
        def __getattr__(self, method):
            async def execute(*positional, **keywords):
                recorded.append((self.mode, method, positional, keywords))
                return {"success": True, "operation": method, "positional": positional, "keywords": keywords}
            return execute

    monkeypatch.setattr(server, "SSHVMConnector", lambda: SpyConnector("ssh"))
    monkeypatch.setattr(server, "LocalVMConnector", lambda: SpyConnector("agent"))

    async def governed(connector, **kwargs):
        recorded.append((connector.mode, "run_governed_change", (), kwargs))
        return {"success": True, "status": "validated_test_only", "kwargs": kwargs}
    monkeypatch.setattr(server, "run_governed_change", governed)
    monkeypatch.setattr(server, "verify_claim", lambda claims, signature, **kw: None)
    ssh_out = await server._call("vm", name, args)
    agent_out = await server._call("vm_agent", name, args)
    assert ssh_out == agent_out, name
    assert len(recorded) == 2, (name, recorded)
    assert recorded[0][0] == "ssh"
    assert recorded[1][0] == "agent"
    assert recorded[0][1:] == recorded[1][1:], name


def test_agent_inherits_every_ssh_vm_business_operation():
    """No read/write implementation is independently forked or silently omitted."""
    assert server._TOOL_SCHEMAS["vm_agent"] == server._TOOL_SCHEMAS["vm"]
    assert set(server._TOOL_SCHEMAS["vm"]) == (
        VMEdgeMCPClient.READ_TOOLS | VMEdgeMCPClient.WRITE_TOOLS
    )
    for tool in server._TOOL_SCHEMAS["vm"]:
        if tool in {"collect_vm_metrics", "config_change_validate", "config_change_apply"}:
            # Edge adapter aliases or composed governed operations.
            continue
        operation = getattr(SSHVMConnector, tool)
        assert inspect.iscoroutinefunction(operation), tool
        assert getattr(LocalVMConnector, tool) is operation, (
            "Unexpected implementation drift between transports", tool
        )


def test_on_host_agent_overrides_only_transport_and_local_policy():
    assert LocalVMConnector._run is not SSHVMConnector._run
    assert LocalVMConnector._validate_target is not SSHVMConnector._validate_target
    assert LocalVMConnector._validate_service is not SSHVMConnector._validate_service
    for forbidden in ("_run_key", "_run_password"):
        # These remain on the inherited class for legacy compatibility only;
        # all public tool paths must call the overridden _run instead.
        assert forbidden not in LocalVMConnector.__dict__
    for forbidden in ("shell", "ssh", "execute_command", "powershell"):
        assert forbidden not in server._TOOL_SCHEMAS["vm_agent"]
