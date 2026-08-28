from __future__ import annotations

import pytest
from pydantic import ValidationError

from mcp_servers.vm_management.config import VMManagementSettings
from mcp_servers.vm_management.inventory import VMInventory, VMRecord
from mcp_servers.vm_management.service import VMManagementService
from mcp_servers.vm_management.transports.base import VMTransport


class FakeTransport(VMTransport):
    def __init__(self, fail: bool = False):
        self.fail = fail
        self.calls = []

    async def collect_vm_metrics(self, vm):
        self.calls.append(("collect_vm_metrics", vm.id))
        return {"metrics": {"load_1m": 0.1}}

    async def service_status(self, vm, service):
        self.calls.append(("service_status", vm.id, service))
        return {"service": service, "status": {"ActiveState": "active"}}

    async def process_snapshot(self, vm):
        self.calls.append(("process_snapshot", vm.id))
        return {"processes": ["1 init 0.0 0.1"]}

    async def restart_service(self, vm, service):
        if self.fail:
            raise RuntimeError("executor_failed")
        self.calls.append(("restart_service", vm.id, service))
        return {"service": service, "active_state": "active"}


def settings(**overrides):
    data = dict(
        REQUIRE_AUTH=False,
        WRITE_ENABLED=False,
        SSH_STRICT_HOST_KEY_CHECKING=False,
    )
    data.update(overrides)
    return VMManagementSettings(**data)


def inventory():
    return VMInventory([
        VMRecord(
            id="lb-01",
            hostname="lb-01",
            ip="10.100.6.199",
            environment="test",
            role="load-balancer",
            ssh_user="root",
            credential_ref="TEST_KEY",
            allowed_operations=["collect_vm_metrics", "service_status", "process_snapshot", "restart_service"],
            allowed_services=["haproxy"],
        )
    ])


def test_unknown_target_is_rejected():
    with pytest.raises(PermissionError, match="vm_target_not_authorized"):
        inventory().resolve("10.100.6.250")


def test_unauthorized_service_is_rejected():
    with pytest.raises(PermissionError, match="vm_service_not_authorized"):
        inventory().authorize("lb-01", "service_status", "postgresql")


def test_inventory_rejects_unknown_operation():
    with pytest.raises(ValueError, match="unknown_allowed_operations"):
        VMRecord(
            id="x", hostname="x", ip="127.0.0.1", environment="test", role="test",
            ssh_user="root", credential_ref="KEY", allowed_operations=["execute_command"], allowed_services=[]
        )


def test_production_forbids_password_authentication():
    with pytest.raises(ValidationError, match="password_auth_forbidden"):
        VMManagementSettings(
            ENVIRONMENT="production",
            REQUIRE_AUTH=True,
            READ_TOKEN="read-token",
            WRITE_TOKEN="write-token",
            SSH_AUTH_MODE="password",
            SSH_STRICT_HOST_KEY_CHECKING=True,
        )


def test_production_requires_strict_host_key_checking():
    with pytest.raises(ValidationError, match="strict_host_key_checking_required"):
        VMManagementSettings(
            ENVIRONMENT="production",
            REQUIRE_AUTH=True,
            READ_TOKEN="read-token",
            WRITE_TOKEN="write-token",
            SSH_AUTH_MODE="key",
            SSH_STRICT_HOST_KEY_CHECKING=False,
        )


@pytest.mark.asyncio
async def test_read_operation_does_not_require_approval():
    transport = FakeTransport()
    service = VMManagementService(settings(), inventory(), transport)
    result = await service.call("service_status", {"target": "10.100.6.199", "service": "haproxy"})
    assert result["success"] is True
    assert result["execution"]["mode"] == "read"


@pytest.mark.asyncio
async def test_write_is_fail_closed_by_default():
    service = VMManagementService(settings(), inventory(), FakeTransport())
    with pytest.raises(PermissionError, match="vm_write_disabled"):
        await service.call("restart_service", {"target": "lb-01", "service": "haproxy", "approval_id": "11111111-1111-1111-1111-111111111111"})


@pytest.mark.asyncio
async def test_write_requires_well_formed_approval():
    service = VMManagementService(settings(WRITE_ENABLED=True), inventory(), FakeTransport())
    with pytest.raises(PermissionError, match="vm_valid_approval_id_required"):
        await service.call("restart_service", {"target": "lb-01", "service": "haproxy", "approval_id": "bad"})


@pytest.mark.asyncio
async def test_approved_restart_is_bound_to_inventory_service():
    transport = FakeTransport()
    service = VMManagementService(settings(WRITE_ENABLED=True), inventory(), transport)
    result = await service.call("restart_service", {
        "target": "lb-01",
        "service": "haproxy",
        "approval_id": "11111111-1111-1111-1111-111111111111",
    })
    assert result["execution"]["mode"] == "write"
    assert result["execution"]["approval_id"]
    assert transport.calls == [("restart_service", "lb-01", "haproxy")]


@pytest.mark.asyncio
async def test_transport_failure_is_not_reported_as_success():
    service = VMManagementService(settings(WRITE_ENABLED=True), inventory(), FakeTransport(fail=True))
    with pytest.raises(RuntimeError, match="executor_failed"):
        await service.call("restart_service", {
            "target": "lb-01", "service": "haproxy",
            "approval_id": "11111111-1111-1111-1111-111111111111",
        })
