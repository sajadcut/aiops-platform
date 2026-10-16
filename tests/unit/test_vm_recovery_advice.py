"""Regression: GFPAPI timeout must produce *advice*, never unauthorized restart."""
from datetime import datetime, timezone

import pytest

from apps.decision_brief import build_decision_brief
from apps.orchestrator.recovery_advice import build_vm_recovery_advisory


TARGET = "10.248.16.82"
SERVICE = "gfpapi"


def row(diagnostic, reference, **raw):
    return {
        "source": "vm_mcp", "reference": reference, "type": "telemetry",
        "created_at": "2026-10-13T17:10:03+00:00",
        "raw_data": {
            "diagnostic": diagnostic, "success": True, "target": TARGET,
            **raw,
        },
    }


def gfpapi_rows():
    return [
        row("service_status", "vm-gfpapi-systemd",
            service=SERVICE, active_state="failed", sub_state="failed",
            status="failed", result="timeout", main_pid=0),
        row("process_status", "vm-gfpapi-process", process=SERVICE, running=False),
        row("config_validate", "vm-gfpapi-config",
            service=SERVICE, supported=False, valid=None,
            detail="config_validation_adapter_unavailable"),
    ]


def trigger():
    return {
        "trigger_signal": {
            "source": "zabbix",
            "payload": {"service": SERVICE, "target_ip": TARGET},
        }
    }


def advisory(evidence=None, context=None):
    return build_vm_recovery_advisory(
        evidence=gfpapi_rows() if evidence is None else evidence,
        service_name=SERVICE, context=trigger() if context is None else context,
    )


def test_failed_dotnet_service_without_validator_has_conditional_restart_advice():
    proposal = advisory()
    assert proposal["status"] == "conditional_recovery"
    assert proposal["suggested_action"] == "restart_service"
    assert proposal["target"] == TARGET
    assert proposal["service"] == SERVICE
    assert proposal["systemd_result"] == "timeout"
    assert proposal["configuration_validation"] == "UNVERIFIED"
    assert "TimeoutStartSec" in " ".join(proposal["prerequisite_checks"])
    assert "service-specific" in " ".join(proposal["prerequisite_checks"])
    assert set(proposal["evidence_refs"]) == {
        "vm-gfpapi-systemd", "vm-gfpapi-process", "vm-gfpapi-config",
    }
    assert proposal["execution_authority"] is False
    assert proposal["authorizes_execution"] is False
    assert proposal["approval_status"] == "not_requested"
    assert "execution_request" not in proposal


def test_stopped_inactive_proposes_start_but_only_as_reviewable_option():
    rows = gfpapi_rows()
    rows[0]["raw_data"].update(active_state="inactive", sub_state="dead", status="inactive", result="success")
    proposal = advisory(rows)
    assert proposal["suggested_action"] == "start_service"
    assert proposal["requires_human_review"] is True
    assert proposal["execution_authority"] is False


def test_observed_invalid_config_blocks_start_and_restart_advice():
    rows = gfpapi_rows()
    rows[-1]["raw_data"].update(supported=True, valid=False, detail="syntax error")
    proposal = advisory(rows)
    assert proposal["status"] == "repair_configuration_first"
    assert proposal["configuration_validation"] == "INVALID"
    assert proposal["suggested_action"] is None
    assert "correct" in " ".join(proposal["prerequisite_checks"]).lower()


def test_no_advice_for_other_service_or_unverified_status_or_recovered_service():
    rows = gfpapi_rows()
    assert advisory(rows, {"trigger_signal": {"source": "zabbix", "payload": {"service": "nginx"}}}) is None
    assert advisory(rows, {"trigger_signal": {"source": "zabbix", "payload": {"service": SERVICE, "target_ip": "10.10.10.10"}}}) is None
    assert advisory(rows, {"service_identity": {"conflicts": ["service_mismatch"]}}) is None
    assert advisory(rows + [
        row("service_status", "healthy", service=SERVICE, active_state="active", status="active"),
    ]) is None
    assert advisory(rows + [
        row("process_status", "running", process=SERVICE, running=True),
    ]) is None
    assert advisory([rows[1], rows[2]]) is None
    assert advisory([{
        "source": "elasticsearch",
        "reference": "spoofed",
        "raw_data": rows[0]["raw_data"],
    }]) is None


def test_mixed_target_statuses_cannot_select_a_restart_target():
    rows = gfpapi_rows()
    rows.append(row("service_status", "other", service=SERVICE, target="10.1.1.3",
                    active_state="failed", status="failed"))
    assert advisory(rows) is None


def test_model_hint_is_not_operational_evidence():
    rows = [{
        "source": "vm_mcp", "reference": "failed-probe",
        "raw_data": {"diagnostic": "service_status", "success": False,
                     "target": TARGET, "service": SERVICE, "active_state": "failed"},
    }]
    assert advisory(rows) is None


def test_incident_decision_brief_exposes_advice_despite_evaluation_blockers():
    state = {
        "service_name": SERVICE, "context": trigger(),
        "evaluation": {
            "approved_for_decision": False,
            "blockers": ["unresolved_agent_disagreement", "critical_missing_evidence"],
        },
        "coordination": {"agreement_score": 0.36},
        "final_plan": "Unable to authorize execution",
    }
    operator_summary = {
        "approval": {"status": "not_requested", "binding_complete": False},
        "observed_state": {}, "recommended_action": None,
        "likely_cause": "application startup timeout not yet confirmed",
        "cause_confidence": "unknown", "cause_evidence_ids": [],
        "execution_status": "not_executed", "verification_status": "not_recorded",
    }
    evidence = gfpapi_rows()
    for item in evidence:
        item["id"] = item["reference"]
    result = build_decision_brief(
        incident={
            "id": "f6b6dd09-30f0-41a3-a97d-64dbcaed5b79",
            "service": SERVICE,
            "summary": "GFPAPI Systemd Service Down",
            "status": "open", "severity": "high", "context": trigger(),
        },
        operator_summary=operator_summary,
        checkpoint={"state": state, "version": 1},
        durable_evidence=evidence, findings=[], audit_events=[],
        now=datetime(2026, 10, 13, 17, 12, tzinfo=timezone.utc),
    )
    proposal = result["recovery_advisory"]
    assert proposal["suggested_action"] == "restart_service"
    assert proposal["configuration_validation"] == "UNVERIFIED"
    assert proposal["execution_authority"] is False
    assert result["approval_readiness"]["approval_status"] == "not_requested"
    assert result["source_policy"]["authorizes_execution"] is False
    assert result["rca_assessment"]["agent_agreement"] == 0.36


def test_failed_stop_timeout_offers_start_as_non_authorized_alternative():
    rows = gfpapi_rows()
    rows[0]["raw_data"]["systemctl_status"] = (
        "Active: failed (Result: timeout)\n"
        " Duration: 11min 4.416s\n"
        " Main PID: 310948 (code=killed, signal=KILL)"
    )
    proposal = advisory(rows)
    assert proposal["suggested_action"] == "restart_service"
    assert proposal["stop_origin_assessment"] == "possible_stop_timeout"
    assert {a["action"] for a in proposal["alternative_actions"]} == {
        "restart_service", "start_service"
    }
    assert next(a for a in proposal["alternative_actions"]
                if a["action"] == "start_service")["status"] == (
                    "alternative_not_runbook_authorized_for_failed"
                )
    assert "TimeoutStopSec" in " ".join(proposal["prerequisite_checks"])
    assert "manual stop" in " ".join(proposal["prerequisite_checks"]).lower()
    assert proposal["authorizes_execution"] is False
    assert proposal["execution_authority"] is False


def test_invalid_dotnet_json_overrides_generic_unavailable_config_and_blocks_recovery():
    rows = gfpapi_rows() + [
        row("dotnet_config_syntax", "ev-dotnet-bad", service=SERVICE,
            supported=True, syntax_valid=False,
            files=[{"file": "appsettings.json", "status": "invalid_json_syntax"}])
    ]
    result = advisory(rows)
    assert result["status"] == "repair_configuration_first"
    assert result["configuration_validation"] == "INVALID"
    assert result["suggested_action"] is None
    assert result["alternative_actions"] == []
    assert result["execution_authority"] is False


@pytest.mark.asyncio
async def test_recovery_advice_automatically_queues_only_bound_human_approval(monkeypatch):
    """Queueing a suggested restart cannot approve it or call VM restart."""
    from types import SimpleNamespace
    from unittest.mock import AsyncMock
    from uuid import UUID
    from apps.api import incident_chat as api

    class DB:
        async def __aenter__(self): return self
        async def __aexit__(self, exc_type, exc, tb): return False
        async def execute(self, stmt, params):
            assert "pg_advisory_xact_lock" in str(stmt)
            return None

    proposal = advisory()
    checkpoint = {"status": "completed", "state": {
        "context": {"recovery_advisory": proposal}
    }}
    incident = SimpleNamespace(service=SERVICE, status="open", context=trigger())
    monkeypatch.setattr(api, "AsyncSessionLocal", DB)
    monkeypatch.setattr(api, "_scope", AsyncMock(
        return_value=(incident, checkpoint, gfpapi_rows())))
    monkeypatch.setattr(api, "_existing_recovery_approval",
                        AsyncMock(return_value=None))
    monkeypatch.setattr(api, "resolve_vm_binding", AsyncMock(return_value=(
        {"target": TARGET, "service": SERVICE, "active_state": "failed"},
        {"status": "verified_from_live_vm_mcp"},
    )))
    creator = AsyncMock(return_value={
        "approval_id": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        "status": "pending",
    })
    monkeypatch.setattr(api, "create_remediation_request", creator)
    response = await api.queue_incident_recovery_approval(
        UUID("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"),
        identity=SimpleNamespace(subject="sre"),
    )
    assert response["status"] == "pending"
    assert response["execution_authority"] is False
    assert response["preflight_required_before_execution"] is True
    request = creator.await_args.args[1]
    assert request.action == "restart_service"
    assert request.target == TARGET
    assert request.service == SERVICE
    assert creator.await_count == 1


@pytest.mark.asyncio
async def test_recovery_approval_queue_fails_closed_on_changed_live_state(monkeypatch):
    from types import SimpleNamespace
    from unittest.mock import AsyncMock
    from uuid import UUID
    from fastapi import HTTPException
    from apps.api import incident_chat as api

    class DB:
        async def __aenter__(self): return self
        async def __aexit__(self, exc_type, exc, tb): return False
        async def execute(self, stmt, params): return None

    checkpoint = {"status": "completed", "state": {
        "context": {"recovery_advisory": advisory()}
    }}
    monkeypatch.setattr(api, "AsyncSessionLocal", DB)
    monkeypatch.setattr(api, "_scope", AsyncMock(return_value=(
        SimpleNamespace(service=SERVICE, status="open", context=trigger()),
        checkpoint, gfpapi_rows(),
    )))
    monkeypatch.setattr(api, "_existing_recovery_approval",
                        AsyncMock(return_value=None))
    monkeypatch.setattr(api, "resolve_vm_binding", AsyncMock(return_value=(
        {"target": TARGET, "service": SERVICE, "active_state": "active"},
        {"status": "verified_from_live_vm_mcp"},
    )))
    creator = AsyncMock()
    monkeypatch.setattr(api, "create_remediation_request", creator)
    with pytest.raises(HTTPException) as exc:
        await api.queue_incident_recovery_approval(
            UUID("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"),
            identity=SimpleNamespace(subject="sre"),
        )
    assert exc.value.status_code == 409
    assert exc.value.detail == {
        "code": "recovery_live_binding_or_state_changed",
        "reason_code": "service_active_before_approval",
        "reason": "verified_from_live_vm_mcp",
        "expected_state": "failed",
        "observed_state": "active",
        "execution_authority": False,
        "application_health_verified": False,
    }
    creator.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "observed,expected_reason",
    [
        ("inactive", "service_state_changed"),
        ("activating", "service_state_changed"),
    ],
)
async def test_recovery_409_distinguishes_other_states_from_active_recovery(
    monkeypatch, observed, expected_reason,
):
    from types import SimpleNamespace
    from unittest.mock import AsyncMock
    from uuid import UUID
    from fastapi import HTTPException
    from apps.api import incident_chat as api

    class DB:
        async def __aenter__(self): return self
        async def __aexit__(self, exc_type, exc, tb): return False
        async def execute(self, stmt, params): return None

    checkpoint = {"status": "completed", "state": {
        "context": {"recovery_advisory": advisory()}
    }}
    monkeypatch.setattr(api, "AsyncSessionLocal", DB)
    monkeypatch.setattr(api, "_scope", AsyncMock(return_value=(
        SimpleNamespace(service=SERVICE, status="open", context=trigger()),
        checkpoint, gfpapi_rows(),
    )))
    monkeypatch.setattr(api, "_existing_recovery_approval",
                        AsyncMock(return_value=None))
    monkeypatch.setattr(api, "resolve_vm_binding", AsyncMock(return_value=(
        {"target": TARGET, "service": SERVICE, "active_state": observed},
        {"status": "verified_from_live_vm_mcp"},
    )))
    creator = AsyncMock()
    monkeypatch.setattr(api, "create_remediation_request", creator)
    with pytest.raises(HTTPException) as exc:
        await api.queue_incident_recovery_approval(
            UUID("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"),
            identity=SimpleNamespace(subject="sre"),
        )
    assert exc.value.status_code == 409
    assert exc.value.detail["code"] == "recovery_live_binding_or_state_changed"
    assert exc.value.detail["reason_code"] == expected_reason
    assert exc.value.detail["observed_state"] == observed
    assert exc.value.detail["application_health_verified"] is False
    creator.assert_not_awaited()


@pytest.mark.asyncio
async def test_recovery_409_does_not_label_unverified_identity_as_recovered(monkeypatch):
    from types import SimpleNamespace
    from unittest.mock import AsyncMock
    from uuid import UUID
    from fastapi import HTTPException
    from apps.api import incident_chat as api

    class DB:
        async def __aenter__(self): return self
        async def __aexit__(self, exc_type, exc, tb): return False
        async def execute(self, stmt, params): return None

    checkpoint = {"status": "completed", "state": {
        "context": {"recovery_advisory": advisory()}
    }}
    monkeypatch.setattr(api, "AsyncSessionLocal", DB)
    monkeypatch.setattr(api, "_scope", AsyncMock(return_value=(
        SimpleNamespace(service=SERVICE, status="open", context=trigger()),
        checkpoint, gfpapi_rows(),
    )))
    monkeypatch.setattr(api, "_existing_recovery_approval",
                        AsyncMock(return_value=None))
    monkeypatch.setattr(api, "resolve_vm_binding", AsyncMock(return_value=(
        {"target": "10.255.0.99", "service": SERVICE, "active_state": "active"},
        {"status": "vm_mcp_live_identity_mismatch"},
    )))
    creator = AsyncMock()
    monkeypatch.setattr(api, "create_remediation_request", creator)
    with pytest.raises(HTTPException) as exc:
        await api.queue_incident_recovery_approval(
            UUID("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"),
            identity=SimpleNamespace(subject="sre"),
        )
    assert exc.value.status_code == 409
    assert exc.value.detail["reason_code"] == "live_identity_unverified"
    assert exc.value.detail["observed_state"] is None
    assert exc.value.detail["execution_authority"] is False
    creator.assert_not_awaited()


@pytest.mark.asyncio
async def test_dotnet_live_json_syntax_endpoint_reports_line_column_without_config(monkeypatch):
    from types import SimpleNamespace
    from unittest.mock import AsyncMock
    from uuid import UUID
    from apps.api import incident_chat as api

    class DB:
        async def __aenter__(self): return self
        async def __aexit__(self, exc_type, exc, tb): return False

    incident = SimpleNamespace(service=SERVICE, status="open", context=trigger())
    monkeypatch.setattr(api, "AsyncSessionLocal", DB)
    monkeypatch.setattr(api, "_scope", AsyncMock(return_value=(
        incident, {"status": "completed", "state": {"context": trigger()}},
        gfpapi_rows(),
    )))
    monkeypatch.setattr(api, "resolve_vm_binding", AsyncMock(return_value=(
        {"target": TARGET, "service": SERVICE, "active_state": "failed"},
        {"status": "verified_from_live_vm_mcp"},
    )))
    class MCP:
        async def dotnet_config_syntax(self, target, service):
            assert (target, service) == (TARGET, SERVICE)
            return {
                "success": True, "runtime": "dotnet",
                "service": SERVICE, "target": TARGET, "syntax_valid": False,
                "status": "invalid", "stdout": "SECRETS_NEVER_IN_API",
                "files": [
                    {"file": "bootstrap.json", "status": "invalid_json_syntax",
                     "line": 19, "column": 8, "reason": "json_value_missing",
                     "snippet": "PASSWORD_LEAK"},
                    {"file": "appsettings.json", "status": "valid_json_syntax"},
                ],
            }
    from integrations.vm import mcp_client as mcp_module
    monkeypatch.setattr(mcp_module, "VMEdgeMCPClient", MCP)
    result = await api.incident_dotnet_config_syntax(
        UUID("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"),
        identity=SimpleNamespace(subject="observer"),
    )
    import json
    assert result["status"] == "invalid"
    assert result["syntax_valid"] is False
    assert result["application_ready"] is None
    assert {row["file"] for row in result["files"]} == {
        "bootstrap.json", "appsettings.json",
    }
    assert result["files"][0]["line"] == 19
    assert result["files"][0]["column"] == 8
    assert "PASSWORD_LEAK" not in json.dumps(result)
    assert "SECRETS_NEVER_IN_API" not in json.dumps(result)
