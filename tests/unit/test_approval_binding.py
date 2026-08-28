import pytest
from fastapi import HTTPException

from apps.api.execution import _validate_approval_binding
from apps.approval_service.binding import bind_execution_metadata


BASE_EXECUTION = {
    "incident_id": "incident-1",
    "action": "restart_service",
    "target": "vm01",
    "tool_name": "ssh_vm",
    "parameters": {"service": "nginx"},
    "timeout": 30,
}
BASE_APPROVAL = {
    "approval_id": "approval-1",
    "incident_id": "incident-1",
    "action": "restart_service",
    "status": "approved",
    "metadata": bind_execution_metadata({}, BASE_EXECUTION, "incident-1"),
}


def test_matching_approval_binding_is_accepted():
    _validate_approval_binding(BASE_APPROVAL, dict(BASE_EXECUTION))


@pytest.mark.parametrize(
    "field,value",
    [
        ("incident_id", "incident-2"),
        ("action", "stop_service"),
        ("target", "vm02"),
        ("tool_name", "mock_executor"),
        ("parameters", {"service": "postgresql"}),
        ("timeout", 120),
    ],
)
def test_approval_cannot_be_replayed_for_different_request(field, value):
    payload = dict(BASE_EXECUTION)
    payload[field] = value
    with pytest.raises(HTTPException) as exc:
        _validate_approval_binding(BASE_APPROVAL, payload)
    assert exc.value.status_code == 409


def test_approval_id_requires_incident_binding():
    payload = dict(BASE_EXECUTION)
    payload.pop("incident_id")
    with pytest.raises(HTTPException) as exc:
        _validate_approval_binding(BASE_APPROVAL, payload)
    assert exc.value.status_code == 400


def test_legacy_approval_without_fingerprint_fails_closed():
    approval = dict(BASE_APPROVAL)
    approval["metadata"] = {"target": "vm01", "tool_name": "ssh_vm", "binding_complete": True}
    with pytest.raises(HTTPException) as exc:
        _validate_approval_binding(approval, dict(BASE_EXECUTION))
    assert exc.value.status_code == 409
