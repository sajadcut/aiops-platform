import pytest
from fastapi import HTTPException

from apps.api.execution import _validate_approval_binding


BASE_APPROVAL = {
    "approval_id": "approval-1",
    "incident_id": "incident-1",
    "action": "restart_service",
    "status": "approved",
    "metadata": {"target": "vm01", "tool_name": "ssh_vm"},
}


def test_matching_approval_binding_is_accepted():
    _validate_approval_binding(
        BASE_APPROVAL,
        {
            "incident_id": "incident-1",
            "action": "restart_service",
            "target": "vm01",
            "tool_name": "ssh_vm",
        },
    )


@pytest.mark.parametrize(
    "field,value",
    [
        ("incident_id", "incident-2"),
        ("action", "stop_service"),
        ("target", "vm02"),
        ("tool_name", "mock_executor"),
    ],
)
def test_approval_cannot_be_replayed_for_different_request(field, value):
    payload = {
        "incident_id": "incident-1",
        "action": "restart_service",
        "target": "vm01",
        "tool_name": "ssh_vm",
    }
    payload[field] = value
    with pytest.raises(HTTPException) as exc:
        _validate_approval_binding(BASE_APPROVAL, payload)
    assert exc.value.status_code == 409


def test_approval_id_requires_incident_binding():
    payload = {"action": "restart_service", "target": "vm01", "tool_name": "ssh_vm"}
    with pytest.raises(HTTPException) as exc:
        _validate_approval_binding(BASE_APPROVAL, payload)
    assert exc.value.status_code == 400


def test_bound_parameters_cannot_be_changed_after_approval():
    approval = {
        **BASE_APPROVAL,
        "metadata": {
            "target": "vm01",
            "tool_name": "ssh_vm",
            "parameters": {"service": "haproxy"},
        },
    }
    with pytest.raises(HTTPException) as exc:
        _validate_approval_binding(
            approval,
            {
                "incident_id": "incident-1",
                "action": "restart_service",
                "target": "vm01",
                "tool_name": "ssh_vm",
                "parameters": {"service": "postgresql"},
            },
        )
    assert exc.value.status_code == 409
    assert "parameters" in str(exc.value.detail).lower()


def test_legacy_remediation_service_binding_is_enforced():
    approval = {
        **BASE_APPROVAL,
        "metadata": {
            "target": "vm01",
            "tool_name": "ssh_vm",
            "service": "haproxy",
        },
    }
    with pytest.raises(HTTPException) as exc:
        _validate_approval_binding(
            approval,
            {
                "incident_id": "incident-1",
                "action": "restart_service",
                "target": "vm01",
                "tool_name": "ssh_vm",
                "parameters": {"service": "nginx"},
            },
        )
    assert exc.value.status_code == 409
    assert "service" in str(exc.value.detail).lower()
