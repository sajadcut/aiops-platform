"""Regression for live Incident validate-config 409 before human Approval.

The signed intent is checked in pending_validation, without turning that
status into an executable Approval or relaxing digest/tamper protection.
"""
import copy

import pytest
from fastapi import HTTPException

from apps.api.config_change_execution import _fields
from apps.approval_service.binding import (
    assert_bound, assert_config_request_bound, bind_metadata,
)

INCIDENT = "5258665a-a575-4303-847f-c5fcdb7f4d7c"
SOURCE = "481c660f85f0732f37dce0426131a8b0ecd4edcfd2132c93d7f9fec44c3e2714"
CANDIDATE = "5454fe22d15e1dece28bd01a293c89d429653a3ee5b11c8d32277a41ffd34ffb"
PARAMETERS = {
    "service": "nginx",
    "config_file": "/etc/nginx/nginx.conf",
    "original_sha256": SOURCE,
    "candidate_sha256": CANDIDATE,
    "proposed_change": "remove_extra_opening_brace",
}
TARGET = "10.248.16.82"


def _intent():
    return {
        "incident_id": INCIDENT, "tool_name": "vm_config_change",
        "action": "apply_configuration_change", "target": TARGET,
        "parameters": PARAMETERS, "timeout": 30,
        "runbook_id": "vm-config-change", "runbook_version": "1",
        "rollback": False,
    }


def _approval(status="pending_validation"):
    metadata = bind_metadata(
        {"workflow": "config_change", "isolated_validation": False, **PARAMETERS},
        **_intent(),
    )
    return {
        "approval_id": "8034ccdd-4a83-4cef-afbd-c7791396a4d8",
        "incident_id": INCIDENT,
        "action": "apply_configuration_change",
        "risk_level": "high",
        "status": status,
        "metadata": metadata,
    }


@pytest.mark.parametrize("status", ["pending_validation", "pending", "approved"])
def test_config_ticket_binding_works_in_each_legitimate_review_state(status):
    approval = _approval(status)
    assert _fields(approval)["candidate_sha256"] == CANDIDATE
    assert_config_request_bound(approval, **_intent())


def test_preapproval_ticket_cannot_be_used_as_executable_approval():
    with pytest.raises(ValueError, match="approval_not_approved"):
        assert_bound(_approval(), **_intent())


@pytest.mark.parametrize("status", ["rejected", "expired", "consumed"])
def test_terminal_config_ticket_is_not_accepted_as_pending_validation(status):
    with pytest.raises(HTTPException) as exc:
        _fields(_approval(status))
    assert exc.value.status_code == 409
    assert exc.value.detail == "config_change_binding_changed"


@pytest.mark.parametrize("field,bad", [
    ("target", "10.248.16.83"),
    ("candidate_sha256", "a" * 64),
    ("config_file", "/etc/nginx/other.conf"),
    ("service", "haproxy"),
    ("proposed_change", "remove_trailing_json_comma"),
    ("binding_digest", "0" * 64),
])
def test_config_ticket_rejects_drift_or_tampering_during_validation(field, bad):
    approval = _approval()
    approval["metadata"][field] = bad
    with pytest.raises(HTTPException) as exc:
        _fields(approval)
    assert exc.value.status_code == 409
    assert exc.value.detail == "config_change_binding_changed"


def test_preapproval_ticket_requires_exact_high_risk_and_workflow():
    for field, value in (
        ("risk_level", "low"),
        ("action", "restart_service"),
    ):
        item = _approval()
        item[field] = value
        with pytest.raises(HTTPException) as exc:
            _fields(item)
        assert exc.value.status_code == 409
    item = _approval()
    item["metadata"]["binding_complete"] = False
    with pytest.raises(HTTPException) as exc:
        _fields(item)
    assert exc.value.detail == "config_change_binding_changed"
