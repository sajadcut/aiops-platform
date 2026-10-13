"""Security regressions for approval-bound plan/evidence snapshots."""
import pytest

from apps.approval_service.binding import decision_snapshot_digest
from apps.orchestrator.runtime import DurableWorkflowRuntime
from tests.unit.test_runtime_approval_resume import (
    _paused_state, _runtime, FakeApprovalStore, FakeOrchestrator,
)
import apps.orchestrator.runtime as runtime_module


def test_decision_digest_is_stable_without_approval_status():
    state = {
        "final_plan": "inspect service then restart after human approval",
        "execution_request": {"action": "restart_service", "target": "vm01"},
        "analysis_results": [{"statement": "nginx inactive", "evidence_ids": ["ev-1"]}],
    }
    base = decision_snapshot_digest(state, "evidence-inventory-1")
    state["approval"] = {"status": "pending", "approval_id": "ap-1"}
    assert decision_snapshot_digest(state, "evidence-inventory-1") == base
    state["approval"]["status"] = "approved"
    assert decision_snapshot_digest(state, "evidence-inventory-1") == base


@pytest.mark.parametrize("mutator", [
    lambda state: state.update(final_plan="changed plan"),
    lambda state: state["analysis_results"].append({"statement": "new contradictory finding"}),
    lambda state: state["live_evidence"].update(evidence=[{"id": "ev-2"}]),
    lambda state: state["evaluation"].update(confidence=0.1),
    lambda state: state["execution_request"].update(target="vm02"),
])
def test_approval_snapshot_rejects_meaningful_plan_or_evidence_changes(mutator):
    state = {
        "final_plan": "restart only if human approved",
        "analysis_results": [{"statement": "nginx down"}],
        "live_evidence": {"evidence": [{"id": "ev-1"}]},
        "evaluation": {"confidence": 0.9},
        "execution_request": {"action": "restart_service", "target": "vm01"},
    }
    earlier = decision_snapshot_digest(state, "inventory-1")
    mutator(state)
    assert decision_snapshot_digest(state, "inventory-1") != earlier


def test_new_durable_evidence_inventory_always_invalidates_snapshot():
    state = {"final_plan": "approved plan"}
    assert decision_snapshot_digest(state, "inventory-1") != decision_snapshot_digest(state, "inventory-2")


@pytest.mark.asyncio
async def test_runtime_denies_consumption_after_approved_decision_snapshot_changes(monkeypatch):
    state = _paused_state()
    state["final_plan"] = "original approved plan"
    state["analysis_results"] = [{"statement": "nginx down"}]
    runtime = _runtime(state)
    original = FakeApprovalStore._metadata()
    original["decision_snapshot_digest"] = decision_snapshot_digest(state, None)
    state["final_plan"] = "changed since approval"

    class ApprovalStore(FakeApprovalStore):
        def __init__(self):
            super().__init__()
            self.cancel_calls = []

        async def get(self, approval_id):
            return {
                "approval_id": approval_id, "incident_id": "incident-1",
                "action": "restart_service", "status": "approved",
                "metadata": original,
            }

        async def cancel(self, approval_id, *, reason, metadata_patch=None):
            self.cancel_calls.append((approval_id, reason))
            return {"status": "rejected"}

    runtime.approvals = ApprovalStore()
    monkeypatch.setattr(runtime_module, "E2EOrchestrator", FakeOrchestrator)
    with pytest.raises(ValueError, match="approval_decision_snapshot_changed"):
        await runtime.resume_after_approval("incident-1")

    assert runtime.approvals.consume_calls == []
    assert runtime.approvals.cancel_calls == [
        ("approval-123", "approval_decision_or_evidence_snapshot_changed"),
    ]
    assert runtime.checkpoints.failed is not None


@pytest.mark.asyncio
async def test_runtime_allows_unchanged_bound_decision_to_resume(monkeypatch):
    state = _paused_state()
    state["final_plan"] = "approved plan"
    runtime = _runtime(state)
    metadata = FakeApprovalStore._metadata()
    metadata["decision_snapshot_digest"] = decision_snapshot_digest(state, None)

    class ApprovalStore(FakeApprovalStore):
        async def get(self, approval_id):
            return {
                "approval_id": approval_id, "incident_id": "incident-1",
                "action": "restart_service", "status": "approved",
                "metadata": metadata,
            }

    runtime.approvals = ApprovalStore()
    monkeypatch.setattr(runtime_module, "E2EOrchestrator", FakeOrchestrator)
    result = await runtime.resume_after_approval("incident-1")
    assert runtime.approvals.consume_calls == ["approval-123"]
    assert result["verification_result"]["status"] == "success"


def test_decision_brief_report_does_not_serve_as_approval_authority():
    from apps.decision_brief import build_decision_brief
    view = build_decision_brief(
        incident={"id": "incident-1", "service": "nginx"},
        operator_summary={"approval": {
            "status": "approved", "decision_snapshot_status": "drift_detected",
        }},
        checkpoint={"state": {}}, durable_evidence=[], findings=[],
        audit_events=[],
    )
    assert view["approval_readiness"]["status"] == "new_approval_required"
    assert view["approval_readiness"]["evidence_snapshot_binding"] == "drift_detected"
    assert view["source_policy"]["authorizes_execution"] is False



@pytest.mark.parametrize("status", ["consumed", "rejected", "expired"])
def test_terminal_approval_does_not_report_new_approval_required_after_execution(status):
    from apps.decision_brief import build_decision_brief
    report = build_decision_brief(
        incident={"id": "incident-1", "service": "nginx", "status": "resolved"},
        operator_summary={
            "approval": {
                "status": status, "decision_snapshot_status": "not_applicable",
                "binding_complete": True, "approval_id": "approval-123",
                "action": "start_service", "tool": "ssh_vm", "target": "10.248.16.82",
            },
            "execution_status": "success",
            "verification_status": "success",
        },
        checkpoint={"state": {
            "execution_result": {"success": True},
            "verification_result": {"status": "success"},
        }},
        durable_evidence=[], findings=[], audit_events=[],
    )
    readiness = report["approval_readiness"]
    assert readiness["status"] == "not_pending"
    assert readiness["evidence_snapshot_binding"] == "not_applicable"
    assert readiness["approval_status"] == status
    assert report["execution_outcome"]["status"] == "success"
    assert report["verification_result"]["status"] == "success"
    assert report["source_policy"]["authorizes_execution"] is False


def test_consumed_approval_cannot_turn_post_execution_snapshot_drift_into_new_approval():
    from apps.decision_brief import build_decision_brief
    report = build_decision_brief(
        incident={"id": "incident-1", "service": "nginx"},
        operator_summary={"approval": {
            "status": "consumed", "decision_snapshot_status": "drift_detected",
        }},
        checkpoint={"state": {}}, durable_evidence=[], findings=[], audit_events=[],
    )
    assert report["approval_readiness"]["status"] == "not_pending"
    assert report["approval_readiness"]["evidence_snapshot_binding"] != "drift_detected"


def test_fullscreen_incident_renders_consumed_approval_without_false_drift():
    from pathlib import Path
    js = (Path(__file__).resolve().parents[2] / "dashboards" / "incident-command-room.js").read_text(encoding="utf-8")
    assert "const snapshotBad=(pending||approved)&&" in js
    assert "Approved execution or verification in progress" in js
    assert "Service recovery verified" in js
