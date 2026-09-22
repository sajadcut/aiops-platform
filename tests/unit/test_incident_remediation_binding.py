from uuid import UUID

import pytest
from fastapi import HTTPException

from apps.api.incidents import (
    RemediationRequest,
    _remediation_contract_from_checkpoint,
)


INCIDENT_ID = UUID("11111111-1111-1111-1111-111111111111")


def _checkpoint():
    return {
        "version": 7,
        "state": {
            "execution_request": {
                "tool_name": "ssh_vm",
                "action": "start_service",
                "target": "10.100.6.199",
                "parameters": {
                    "service": "nginx",
                    "target_port": 86,
                    "password": "must-not-be-persisted-in-approval-metadata",
                },
                "timeout": 30,
                "runbook_id": "vm-service-recovery",
                "runbook_version": "1.1",
                "rollback": False,
            },
            "decision": {
                "action": "require_approval",
                "risk_level": "high",
                "suggested_approver": "SRE-Lead",
            },
            "approval": {},
        },
    }


def test_remediation_contract_uses_durable_decision_not_requested_risk():
    payload = RemediationRequest(
        reason="operator wants governed recovery",
        risk_level="low",
        approver="Operator-Supplied",
    )

    contract = _remediation_contract_from_checkpoint(
        INCIDENT_ID,
        _checkpoint(),
        payload,
    )

    assert contract["risk_level"] == "high"
    assert contract["execution_request"]["action"] == "start_service"
    assert contract["decision"]["suggested_approver"] == "SRE-Lead"
    metadata = contract["metadata"]
    assert metadata["binding_complete"] is True
    assert len(metadata["binding_digest"]) == 64
    assert metadata["tool_name"] == "ssh_vm"
    assert metadata["target"] == "10.100.6.199"
    assert metadata["runbook_id"] == "vm-service-recovery"
    assert metadata["runbook_version"] == "1.1"
    assert metadata["workflow_checkpoint_version"] == 7
    assert "password" not in metadata
    assert "must-not-be-persisted-in-approval-metadata" not in str(metadata)


def test_remediation_contract_rejects_incomplete_execution_request():
    checkpoint = _checkpoint()
    checkpoint["state"]["execution_request"]["target"] = ""

    with pytest.raises(HTTPException) as exc:
        _remediation_contract_from_checkpoint(
            INCIDENT_ID,
            checkpoint,
            RemediationRequest(),
        )

    assert exc.value.status_code == 409
    assert exc.value.detail == "remediation_plan_not_ready"


def test_remediation_contract_rejects_non_approval_decision():
    checkpoint = _checkpoint()
    checkpoint["state"]["decision"]["action"] = "auto_execute"

    with pytest.raises(HTTPException) as exc:
        _remediation_contract_from_checkpoint(
            INCIDENT_ID,
            checkpoint,
            RemediationRequest(),
        )

    assert exc.value.status_code == 409
    assert exc.value.detail == "remediation_approval_not_required_by_decision"


def test_remediation_contract_rejects_missing_checkpoint_state():
    with pytest.raises(HTTPException) as exc:
        _remediation_contract_from_checkpoint(
            INCIDENT_ID,
            {"version": 1, "state": None},
            RemediationRequest(),
        )

    assert exc.value.status_code == 409
    assert exc.value.detail == "remediation_workflow_checkpoint_missing"
