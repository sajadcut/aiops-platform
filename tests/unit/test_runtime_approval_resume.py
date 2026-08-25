import pytest

import apps.orchestrator.runtime as runtime_module
from apps.orchestrator.runtime import DurableWorkflowRuntime


class FakeCheckpointStore:
    def __init__(self, state):
        self.state = state
        self.completed = None

    async def load(self, incident_id):
        return {"state": self.state, "status": "paused"}

    async def mark_completed(self, incident_id, result):
        self.completed = (incident_id, result)


class FakeApprovalStore:
    async def get(self, approval_id):
        return {
            "approval_id": approval_id,
            "incident_id": "incident-1",
            "action": "restart_service",
            "status": "approved",
        }


class FakeIncidentRepository:
    async def add_findings(self, incident_id, findings):
        return None

    async def commit(self):
        return None


class FakeAuditStore:
    pass


class FakeOrchestrator:
    captured_execution_request = None

    def __init__(self, db=None):
        self.db = db

    async def _execution_node(self, state):
        FakeOrchestrator.captured_execution_request = dict(state["execution_request"])
        state["execution_result"] = {"success": True}
        return state

    async def _verification_node(self, state):
        state["verification_result"] = {"status": "verified"}
        return state

    async def _memory_node(self, state):
        return state

    async def _end_node(self, state):
        state["current_node"] = "end"
        return state


@pytest.mark.asyncio
async def test_resume_injects_persisted_approval_into_execution_request(monkeypatch):
    state = {
        "approval": {"approval_id": "approval-123", "status": "pending"},
        "execution_request": {
            "tool_name": "ssh_vm",
            "action": "restart_service",
            "target": "vm01",
        },
        "findings": [],
    }

    runtime = DurableWorkflowRuntime.__new__(DurableWorkflowRuntime)
    runtime.session = object()
    runtime.checkpoints = FakeCheckpointStore(state)
    runtime.approvals = FakeApprovalStore()
    runtime.incidents = FakeIncidentRepository()
    runtime.audit = FakeAuditStore()

    async def no_audit(_incident_id):
        return None

    runtime._flush_audit = no_audit
    monkeypatch.setattr(runtime_module, "E2EOrchestrator", FakeOrchestrator)

    result = await runtime.resume_after_approval("incident-1")

    assert result["current_node"] == "end"
    assert FakeOrchestrator.captured_execution_request["approval_granted"] is True
    assert FakeOrchestrator.captured_execution_request["approval_id"] == "approval-123"
