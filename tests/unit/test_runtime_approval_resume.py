import pytest

import apps.orchestrator.runtime as runtime_module
from apps.approval_service.binding import bind_metadata
from apps.orchestrator.runtime import DurableWorkflowRuntime


class FakeCheckpointStore:
    def __init__(self, state):
        self.state = state
        self.completed = None
        self.failed = None

    async def load(self, incident_id):
        return {"state": self.state, "status": "paused"}

    async def mark_completed(self, incident_id, result):
        self.completed = (incident_id, result)

    async def mark_failed(self, incident_id, result):
        self.failed = (incident_id, result)


class FakeApprovalStore:
    @staticmethod
    def _metadata():
        return bind_metadata(
            {},
            incident_id="incident-1",
            tool_name="ssh_vm",
            action="restart_service",
            target="vm01",
            parameters={},
            timeout=30,
            runbook_id=None,
            runbook_version=None,
            rollback=False,
        )

    async def get(self, approval_id):
        return {
            "approval_id": approval_id,
            "incident_id": "incident-1",
            "action": "restart_service",
            "status": "approved",
            "metadata": self._metadata(),
        }

    async def consume(self, approval_id):
        return {
            "approval_id": approval_id,
            "incident_id": "incident-1",
            "action": "restart_service",
            "status": "consumed",
            "metadata": self._metadata(),
        }


class FakeIncidentRepository:
    def __init__(self):
        self.statuses = []

    async def add_findings(self, incident_id, findings):
        return None

    async def set_status(self, incident_id, status):
        self.statuses.append((incident_id, status))

    async def commit(self):
        return None


class FakeAuditStore:
    pass


class FakeOrchestrator:
    captured_execution_request = None
    verification_calls = 0

    def __init__(self, db=None):
        self.db = db

    async def _execution_node(self, state):
        FakeOrchestrator.captured_execution_request = dict(state["execution_request"])
        state["execution_result"] = {"success": True}
        return state

    async def _verification_node(self, state):
        FakeOrchestrator.verification_calls += 1
        state["verification_result"] = {"status": "success"}
        return state

    async def _memory_node(self, state):
        return state

    async def _end_node(self, state):
        state["current_node"] = "end"
        return state


class ExecutionFailsOrchestrator(FakeOrchestrator):
    verification_calls = 0

    async def _execution_node(self, state):
        state["execution_result"] = {
            "success": False,
            "execution_blocked": False,
            "reason": "mcp_write_failed",
        }
        return state

    async def _verification_node(self, state):
        ExecutionFailsOrchestrator.verification_calls += 1
        raise AssertionError("verification must not run after failed execution")


class VerificationFailsOrchestrator(FakeOrchestrator):
    async def _verification_node(self, state):
        state["verification_result"] = {"status": "failed", "message": "service still unhealthy"}
        return state



def _paused_state():
    return {
        "approval": {"approval_id": "approval-123", "status": "pending"},
        "execution_request": {
            "tool_name": "ssh_vm",
            "action": "restart_service",
            "target": "vm01",
        },
        "findings": [],
    }


def _runtime(state):
    runtime = DurableWorkflowRuntime.__new__(DurableWorkflowRuntime)
    runtime.session = object()
    runtime.checkpoints = FakeCheckpointStore(state)
    runtime.approvals = FakeApprovalStore()
    runtime.incidents = FakeIncidentRepository()
    runtime.audit = FakeAuditStore()

    async def no_audit(_incident_id):
        return None

    runtime._flush_audit = no_audit
    return runtime


@pytest.mark.asyncio
async def test_resume_injects_persisted_approval_into_execution_request(monkeypatch):
    runtime = _runtime(_paused_state())
    FakeOrchestrator.verification_calls = 0
    monkeypatch.setattr(runtime_module, "E2EOrchestrator", FakeOrchestrator)

    result = await runtime.resume_after_approval("incident-1")

    assert result["current_node"] == "end"
    assert runtime.checkpoints.completed is not None
    assert runtime.checkpoints.failed is None
    assert FakeOrchestrator.captured_execution_request["approval_granted"] is True
    assert FakeOrchestrator.captured_execution_request["approval_id"] == "approval-123"
    assert FakeOrchestrator.verification_calls == 1
    assert runtime.incidents.statuses[-1] == ("incident-1", "resolved")


@pytest.mark.asyncio
async def test_failed_execution_never_runs_verification_or_resolves_incident(monkeypatch):
    runtime = _runtime(_paused_state())
    ExecutionFailsOrchestrator.verification_calls = 0
    monkeypatch.setattr(runtime_module, "E2EOrchestrator", ExecutionFailsOrchestrator)

    result = await runtime.resume_after_approval("incident-1")

    assert result["terminal_reason"] == "mcp_write_failed"
    assert runtime.checkpoints.failed is not None
    assert runtime.checkpoints.completed is None
    assert ExecutionFailsOrchestrator.verification_calls == 0
    assert runtime.incidents.statuses[-1] == ("incident-1", "escalated")


@pytest.mark.asyncio
async def test_failed_verification_never_resolves_incident(monkeypatch):
    runtime = _runtime(_paused_state())
    monkeypatch.setattr(runtime_module, "E2EOrchestrator", VerificationFailsOrchestrator)

    result = await runtime.resume_after_approval("incident-1")

    assert result["execution_result"]["success"] is True
    assert result["verification_result"]["status"] == "failed"
    assert result["terminal_reason"] == "verification_failed"
    assert runtime.checkpoints.failed is not None
    assert runtime.checkpoints.completed is None
    assert runtime.incidents.statuses[-1] == ("incident-1", "escalated")
