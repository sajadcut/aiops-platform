from __future__ import annotations

from fastapi.testclient import TestClient

from mcp_servers.vm_management.app import create_app
from mcp_servers.vm_management.config import VMManagementSettings
from mcp_servers.vm_management.inventory import VMInventory, VMRecord
from mcp_servers.vm_management.transports.base import VMTransport


class FakeTransport(VMTransport):
    async def collect_vm_metrics(self, vm): return {"metrics": {"load_1m": 0.2}}
    async def service_status(self, vm, service): return {"service": service, "status": {"ActiveState": "active"}}
    async def process_snapshot(self, vm): return {"processes": ["1 init"]}
    async def restart_service(self, vm, service): return {"service": service, "active_state": "active"}


def client(write_enabled=True):
    settings = VMManagementSettings(
        REQUIRE_AUTH=True,
        READ_TOKEN="read-token",
        WRITE_TOKEN="write-token",
        WRITE_ENABLED=write_enabled,
        SSH_STRICT_HOST_KEY_CHECKING=False,
    )
    inventory = VMInventory([VMRecord(
        id="lb-01", hostname="lb-01", ip="10.100.6.199", environment="test", role="load-balancer",
        ssh_user="root", credential_ref="KEY",
        allowed_operations=["collect_vm_metrics", "service_status", "process_snapshot", "restart_service"],
        allowed_services=["haproxy"],
    )])
    return TestClient(create_app(settings, inventory, FakeTransport()))


def initialize(c, token="read-token"):
    response = c.post("/mcp", headers={"Authorization": f"Bearer {token}"}, json={
        "jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {"protocolVersion": "2025-03-26", "capabilities": {}, "clientInfo": {"name": "test", "version": "1"}},
    })
    assert response.status_code == 200
    return response.headers["Mcp-Session-Id"]


def test_initialize_and_tools_list():
    with client() as c:
        sid = initialize(c)
        response = c.post("/mcp", headers={"Authorization": "Bearer read-token", "Mcp-Session-Id": sid}, json={
            "jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}
        })
        names = {item["name"] for item in response.json()["result"]["tools"]}
        assert names == {"collect_vm_metrics", "service_status", "process_snapshot", "restart_service"}


def test_read_tool_returns_structured_content():
    with client() as c:
        sid = initialize(c)
        response = c.post("/mcp", headers={"Authorization": "Bearer read-token", "Mcp-Session-Id": sid}, json={
            "jsonrpc": "2.0", "id": 3, "method": "tools/call",
            "params": {"name": "service_status", "arguments": {"target": "lb-01", "service": "haproxy"}},
        })
        assert response.json()["result"]["structuredContent"]["success"] is True


def test_write_requires_write_identity():
    with client() as c:
        sid = initialize(c)
        response = c.post("/mcp", headers={"Authorization": "Bearer read-token", "Mcp-Session-Id": sid}, json={
            "jsonrpc": "2.0", "id": 4, "method": "tools/call",
            "params": {"name": "restart_service", "arguments": {
                "target": "lb-01", "service": "haproxy", "approval_id": "11111111-1111-1111-1111-111111111111"
            }},
        })
        assert response.status_code == 403


def test_write_with_write_identity_and_approval():
    with client() as c:
        sid = initialize(c, "write-token")
        response = c.post("/mcp", headers={"Authorization": "Bearer write-token", "Mcp-Session-Id": sid}, json={
            "jsonrpc": "2.0", "id": 5, "method": "tools/call",
            "params": {"name": "restart_service", "arguments": {
                "target": "lb-01", "service": "haproxy", "approval_id": "11111111-1111-1111-1111-111111111111"
            }},
        })
        assert response.json()["result"]["structuredContent"]["execution"]["mode"] == "write"


def test_malformed_request_is_rejected():
    with client() as c:
        response = c.post("/mcp", headers={"Authorization": "Bearer read-token"}, json={"hello": "world"})
        assert response.status_code == 400
        assert response.json()["error"]["code"] == -32600


def test_authentication_failure():
    with client() as c:
        response = c.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
        assert response.status_code == 401
