"""Incident-chat follow-up must enrich evidence and learning without execution."""
from datetime import datetime, timezone
from uuid import UUID

from apps.incident_followup import followup_evidence, may_reassess, knowledge_candidate


SERVICE = "gfpapi"
BINDING = {"service": SERVICE, "target": "10.248.16.82"}


def test_only_real_live_vm_mcp_diagnostics_can_enter_canonical_evidence():
    row = followup_evidence(
        action="service_status",
        observation={"success": True, "diagnostic": "service_status",
                     "active_state": "failed", "result": "timeout"},
        service=SERVICE, binding=BINDING, reference="chat-mcp:abc",
        now=datetime(2026, 10, 14, tzinfo=timezone.utc),
    )
    assert row["source"] == "vm_mcp"
    assert row["raw_data"]["diagnostic"] == "service_status"
    assert row["raw_data"]["service"] == SERVICE
    assert row["raw_data"]["target"] == BINDING["target"]
    assert row["raw_data"]["result"] == "timeout"
    assert row["raw_data"]["phase"] == "incident_copilot_followup"
    assert row["reference"] == "chat-mcp:abc"
    assert not any("execute" in str(k) for k in row)


def test_no_free_form_ai_cached_elastic_knowledge_failed_or_cross_target_spoof():
    for action, observation, binding in (
        ("answer", {"success": True}, BINDING),
        ("knowledge_search", {"success": True}, BINDING),
        ("elastic_recorded", {"success": True}, BINDING),
        ("service_status", {"success": False}, BINDING),
        ("service_status", {"success": True}, {"service": "nginx", "target": "10.248.16.82"}),
        ("service_status", {"success": True}, None),
        ("elastic_logs", {"success": True, "is_live": False, "searched_service": SERVICE}, None),
        ("elastic_logs", {"success": True, "is_live": True, "searched_service": "nginx"}, None),
    ):
        assert followup_evidence(
            action=action, observation=observation, service=SERVICE,
            binding=binding, reference="chat-mcp:unused",
        ) is None


def test_live_elastic_empty_is_evidence_of_query_not_absence_of_incident():
    row = followup_evidence(
        action="elastic_logs", observation={
            "success": True, "is_live": True, "searched_service": SERVICE,
            "status": "empty", "returned_count": 0, "results": [],
        }, service=SERVICE, binding=None, reference="chat-mcp:elastic",
    )
    assert row["source"] == "elasticsearch"
    assert row["raw_data"]["status"] == "queried"
    assert row["raw_data"]["result_count"] == 0
    assert row["raw_data"]["absence_of_errors_proven"] is False
    assert row["raw_data"]["results_are_sampled"] is True


def test_reanalysis_only_on_terminal_no_action_checkpoint_without_approval():
    safe = {"status": "completed", "state": {"terminal_reason": "no_action_proposed"}}
    assert may_reassess(safe) is True
    assert may_reassess({**safe, "status": "paused"}) is False
    assert may_reassess({**safe, "status": "running"}) is False
    assert may_reassess({"status": "completed", "state": {"approval": {"approval_id": "a"}}}) is False
    assert may_reassess({"status": "completed", "state": {"execution_request": {"action": "restart"}}}) is False
    assert may_reassess(safe, "approved") is False
    assert may_reassess(safe, "consumed") is False
    assert may_reassess(safe, "rejected") is True


def test_cognia_candidate_is_marked_unverified_and_cites_incident():
    incident = UUID("f6b6dd09-30f0-41a3-a97d-64dbcaed5b79")
    title, content = knowledge_candidate(
        incident_id=incident, service=SERVICE, evidence_ref="evidence-123",
        diagnostic="service_logs", state={
            "followup_analysis": {"status": "reassessed_read_only"},
            "analysis_results": [
                {"statement": "Stop timeout is a hypothesis; audit not checked"},
            ],
        },
    )
    assert SERVICE in title
    assert str(incident) in content
    assert "evidence-123" in content
    assert "تأییدشده یا نتیجه بازیابی نیست" in content
    assert "راستی‌آزمایی" in content
    assert "تأیید" in content
    assert "Stop timeout" in content
    assert "اجرا شد" not in content
