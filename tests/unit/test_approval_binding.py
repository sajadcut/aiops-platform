import pytest
from fastapi import HTTPException

from apps.api.execution import _validate_approval_binding
from apps.approval_service.binding import bind_metadata


def _approval():
    return {
        "approval_id": "approval-1",
        "incident_id": "incident-1",
        "action": "restart_service",
        "status": "approved",
        "metadata": bind_metadata(
            {},
            incident_id="incident-1",
            action="restart_service",
            target="vm01",
            tool_name="ssh_vm",
            parameters={"service": "nginx"},
            timeout=30,
            runbook_id="restart-nginx",
            runbook_version="1.0",
            rollback=False,
        ),
    }


def _payload():
    return {
        "incident_id": "incident-1",
        "action": "restart_service",
        "target": "vm01",
        "tool_name": "ssh_vm",
        "parameters": {"service": "nginx"},
        "timeout": 30,
        "runbook_id": "restart-nginx",
        "runbook_version": "1.0",
        "rollback": False,
    }


def test_matching_approval_binding_is_accepted():
    _validate_approval_binding(_approval(), _payload())


@pytest.mark.parametrize(
    "field,value",
    [
        ("incident_id", "incident-2"),
        ("action", "stop_service"),
        ("target", "vm02"),
        ("tool_name", "mock_executor"),
        ("parameters", {"service": "postgresql"}),
        ("timeout", 60),
        ("runbook_id", "other-runbook"),
        ("runbook_version", "2.0"),
        ("rollback", True),
    ],
)
def test_approval_cannot_be_replayed_for_different_request(field, value):
    payload = _payload()
    payload[field] = value
    with pytest.raises(HTTPException) as exc:
        _validate_approval_binding(_approval(), payload)
    assert exc.value.status_code == 409


def test_approval_id_requires_incident_binding():
    payload = _payload()
    payload.pop("incident_id")
    with pytest.raises(HTTPException) as exc:
        _validate_approval_binding(_approval(), payload)
    assert exc.value.status_code == 400


def test_legacy_partial_binding_fails_closed():
    approval = _approval()
    approval["metadata"] = {"target": "vm01", "tool_name": "ssh_vm", "binding_complete": True}
    with pytest.raises(HTTPException) as exc:
        _validate_approval_binding(approval, _payload())
    assert exc.value.status_code == 409
