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
    assert may_reassess({"status": "completed", "state": {"execution_request": {"action": "restart"}}}) is True  # denied/unapproved plan
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


import pytest
from types import SimpleNamespace


@pytest.mark.asyncio
async def test_followup_reassessment_recalculates_agents_without_executing(monkeypatch):
    from apps import incident_followup as mod
    import apps.orchestrator.signal_aware as orchestrator_module
    incident_id = UUID("f6b6dd09-30f0-41a3-a97d-64dbcaed5b79")
    reference_id = UUID("45c76146-a94f-46ae-b0ae-dba2b9b0e7a1")
    calls = []

    class DatabaseResult:
        def __init__(self, value):
            self.value = value
        def scalar_one(self):
            return self.value
        def scalar_one_or_none(self):
            return self.value

    class Database:
        async def execute(self, statement, arguments=None):
            statement_text = str(statement)
            if "FROM approvals" in statement_text:
                return DatabaseResult(None)
            return DatabaseResult(SimpleNamespace(
                id=reference_id, created_at=datetime.now(timezone.utc),
            ))
        async def commit(self):
            calls.append("db_commit")
        async def rollback(self):
            calls.append("rollback")

    class Repo:
        def __init__(self, db): pass
        async def add_evidence(self, iid, evidence):
            calls.append("persist_evidence")
            assert evidence[0]["source"] == "vm_mcp"
        async def add_findings(self, iid, findings):
            calls.append("persist_findings")
            assert findings[0]["finding_type"] == "copilot_followup_vm"
        async def commit(self):
            calls.append("commit_evidence_or_findings")

    class CheckpointStore:
        def __init__(self, db): pass
        async def save(self, iid, state, status):
            calls.append("save_checkpoint")
            assert status == "completed"
            assert state["followup_analysis"]["execution_authority"] is False
            assert state["evaluation"]["approved_for_decision"] is False
            assert not state.get("execution_request")
            assert any(x.get("id") == str(reference_id)
                       for x in state["context"]["evidence"])

    class Audit:
        def __init__(self, db): pass
        async def append(self, event):
            calls.append("audit:" + event["event_type"])

    class Orchestrator:
        registry = SimpleNamespace(enabled_names=lambda: ["vm"])
        coordinator = SimpleNamespace(synthesize=lambda rows: {
            "agreement_score": 0.8, "confidence": 0.8,
        })
        def __init__(self, db): pass
        async def _run_specialists(self, names, state):
            calls.append("run_agents")
            assert names == ["vm"]
            return [{
                "agent_name": "vm", "statement": "Timeout seen; cause not confirmed",
                "evidence_ids": [str(reference_id)], "confidence": 0.8,
            }]
        async def _rca_node(self, state):
            calls.append("rca")
            state["final_plan"] = "Review journal and maintenance audit."
        async def _evaluator_node(self, state):
            calls.append("evaluator")
            state["evaluation"] = {"approved_for_decision": False,
                                   "reason": "human_review_required"}

    async def knowledge_draft(db, **kwargs):
        calls.append("cognia_draft")
        return {"status": "pending_review", "review_id": "draft-123",
                "published_to_cognia": False}

    monkeypatch.setattr(mod, "IncidentRepository", Repo)
    monkeypatch.setattr(mod, "WorkflowCheckpointStore", CheckpointStore)
    monkeypatch.setattr(mod, "PostgreSQLAuditStore", Audit, raising=False)
    # The production module imports the PostgreSQL audit adapter inside the
    # callable; patch that source rather than fabricating execution authority.
    import apps.audit_service.postgres as audits
    monkeypatch.setattr(audits, "PostgreSQLAuditStore", Audit)
    monkeypatch.setattr(orchestrator_module, "SignalAwareE2EOrchestrator", Orchestrator)
    monkeypatch.setattr(mod, "draft_cognia_review", knowledge_draft)
    result = await mod.persist_and_reassess(
        Database(), incident_id=incident_id, incident_service="gfpapi",
        checkpoint={
            "status": "completed",
            "state": {
                "routing": {"selected": ["vm"]},
                "context": {"evidence": [{"source": "zabbix", "reference": "original-alert"}]},
                "execution_request": {"action": "restart_service"},
            },
        },
        action="service_status",
        observation={"success": True, "active_state": "failed", "result": "timeout"},
        binding=BINDING, actor="operator",
    )
    assert result["reassessed"] is True
    assert result["knowledge"]["status"] == "pending_review"
    assert result["knowledge"]["published_to_cognia"] is False
    assert result["evidence_ref"] == str(reference_id)
    assert calls.index("persist_evidence") < calls.index("run_agents")
    assert calls.index("run_agents") < calls.index("evaluator")
    assert "save_checkpoint" in calls
    assert "cognia_draft" in calls
    assert "audit:incident_copilot_followup_integrated" in calls
    assert "execute" not in calls and "approve" not in calls
