"""Regression: GFPAPI timeout must produce *advice*, never unauthorized restart."""
from datetime import datetime, timezone

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
