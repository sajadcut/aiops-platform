"""Config-review operator intent is not a production write approval."""
import pytest
from pydantic import ValidationError

from apps.api.config_change_review import (
    ConfigReviewResponse, _matching_proposal, _hash, _review_progress,
)


def proposal():
    return {
        "status": "candidate_proposed", "service": "nginx",
        "config_file": "/etc/nginx/nginx.conf",
        "original_sha256": "a" * 64,
        "candidate_sha256": "b" * 64,
        "proposed_change": "remove_extra_opening_brace",
        "source_evidence_refs": ["vm-review-103"],
        "validation_status": "STAGED_PASS_NOT_ISOLATED",
        "execution_authority": False, "apply_eligible": False,
    }


def response(decision="request_isolated_validation"):
    return ConfigReviewResponse(
        decision=decision,
        expected_original_sha256="a" * 64,
        expected_candidate_sha256="b" * 64,
    )


def test_operator_response_binds_both_config_hashes_to_server_checkpoint():
    assert _matching_proposal(proposal(), response())
    assert _matching_proposal(proposal(), response("reject"))
    assert _hash("a" * 64)
    assert not _hash("a" * 63)


@pytest.mark.parametrize("key,value", [
    ("status", "needs_read_only_config"),
    ("status", "staging_failed"),
    ("service", "another-service"),
    ("execution_authority", True),
    ("apply_eligible", True),
    ("original_sha256", None),
    ("candidate_sha256", None),
    ("candidate_sha256", "b" * 63),
    ("proposed_change", "arbitrary_llm_patch"),
    ("source_evidence_refs", []),
])
def test_review_rejects_untrusted_or_incomplete_proposals(key,value):
    p=proposal()
    p[key]=value
    assert not _matching_proposal(p, response())


def test_operator_intent_cannot_be_approval_or_apply_command():
    p=proposal()
    assert _matching_proposal(p,response())
    assert p["validation_status"]=="STAGED_PASS_NOT_ISOLATED"
    assert p["execution_authority"] is False
    assert p["apply_eligible"] is False


def test_api_is_guarded_and_exposes_no_execution_authority():
    # Several unrelated test suites replace FastAPI route modules in
    # sys.modules. Verify actual production app registration in a clean
    # interpreter rather than accepting their process-wide mocks.
    import subprocess
    import sys
    from inspect import getsource
    from apps.api.config_change_review import post_config_review_response
    source=getsource(post_config_review_response)
    assert 'require_permission("approve:high_risk")' in source
    assert "ExecutionRequest" not in source
    probe=subprocess.run(
        [sys.executable, "-c",
         "from fastapi.testclient import TestClient; from apps.api.main import app; "
         "c=TestClient(app); "
         "p='/api/v1/incidents/00000000-0000-4000-8000-000000000001/configuration-review-response'; "
         "print('ROUTE_STATUS',c.get(p).status_code,c.post(p,json={}).status_code)"],
        capture_output=True, text=True, timeout=20, check=False,
    )
    assert probe.returncode==0, probe.stderr[-2000:]
    assert "ROUTE_STATUS 401 401" in probe.stdout, probe.stdout[-2000:]

def test_proposed_response_schema_does_not_accept_bogus_hash_types():
    with pytest.raises(ValidationError):
        ConfigReviewResponse(decision="request_isolated_validation",
                             expected_original_sha256=None,
                             expected_candidate_sha256=None)


def test_submitted_request_is_visible_but_never_claims_an_executable_approval():
    state = _review_progress(
        status="awaiting_isolated_validation",
        decision="request_isolated_validation",
        proposal=proposal(),
        created_at="2026-10-15T08:46:33Z",
    )
    assert state["request_recorded"] is True
    assert state["status"] == "awaiting_isolated_validation"
    assert state["config_file"] == "/etc/nginx/nginx.conf"
    assert state["validation_pipeline_status"] == "not_implemented"
    assert state["change_contract_status"] == "not_implemented"
    assert state["approval_status"] == "not_created"
    assert state["approval_id"] is None
    assert state["approval_eligible"] is False
    assert state["execution_authority"] is False
    assert state["production_write_performed"] is False
    assert "isolated_candidate_validation_not_implemented" in state["blocking_reasons"]


def test_unrequested_config_does_not_claim_a_pending_validation_or_approval():
    state = _review_progress(
        status="not_responded", decision=None, proposal=proposal(),
    )
    assert state["request_recorded"] is False
    assert state["blocking_reasons"] == []
    assert state["approval_id"] is None
    assert not state["approval_eligible"]


def test_main_approval_dashboard_distinguishes_config_review_from_real_approval():
    from pathlib import Path
    root = Path(__file__).resolve().parents[2]
    dashboard = (root / "dashboards/approval-actions.js").read_text(encoding="utf-8")
    incident = (root / "dashboards/incident-command-room.js").read_text(encoding="utf-8")
    assert "function configPreApprovalPanel()" in dashboard
    assert "configPreApprovalPanel()" in dashboard
    assert "/configuration-review-response" in dashboard
    assert "در انتظار اعتبارسنجی فنی" in dashboard
    assert "ارسال درخواست به Approval" in incident
    assert "validation_pipeline_status==='not_implemented'" in incident


def test_approved_queue_record_is_still_not_executable_before_validation():
    queued = {
        "approval_id": "11111111-1111-4111-8111-111111111111",
        "status": "pending_validation",
    }
    result = _review_progress(
        status="pending_validation", decision="request_change_approval",
        proposal=proposal(), approval=queued,
    )
    assert result["approval_id"] == queued["approval_id"]
    assert result["approval_queue_registered"] is True
    assert result["approval_status"] == "pending_validation"
    assert result["approval_actionable"] is False
    assert result["execution_authority"] is False
    assert result["production_write_performed"] is False


def test_generic_service_json_candidate_can_enter_same_approval_queue():
    candidate = proposal()
    candidate.update({
        "service": "gfpapi",
        "config_file": "/opt/apps/gfpapi/appsettings.json",
        "proposed_change": "remove_trailing_json_comma",
    })
    assert _matching_proposal(candidate, response("request_change_approval"))
    candidate["proposed_change"] = "remove_extra_opening_brace"
    assert not _matching_proposal(candidate, response("request_change_approval"))


def test_approval_storage_does_not_upgrade_pending_validation_to_pending():
    from inspect import getsource
    from apps.approval_service.postgres import PostgreSQLApprovalStore
    implementation = getsource(PostgreSQLApprovalStore.save_validation_request)
    assert "'pending_validation'" in implementation
    assert "ON CONFLICT DO NOTHING" in implementation
    assert "self.save(" not in implementation
    assert "return stored" in implementation
    approval_route = getsource(__import__(
        "apps.api.execution", fromlist=["approve"]).approve)
    assert "_require_pending(current)" in approval_route
