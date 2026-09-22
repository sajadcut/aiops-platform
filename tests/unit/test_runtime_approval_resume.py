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


class GuardedApprovalStore:
    def __init__(self):
        self.consume_calls = []
        self.cancel_calls = []

    @staticmethod
    def _metadata():
        return bind_metadata(
            {},
            incident_id="incident-1",
            tool_name="ssh_vm",
            action="start_service",
            target="10.100.6.199",
            parameters={"service": "nginx", "target_port": 86},
            timeout=30,
            runbook_id="vm-service-recovery",
            runbook_version="1.1",
            rollback=False,
        )

    async def get(self, approval_id):
        return {
            "approval_id": approval_id,
            "incident_id": "incident-1",
            "action": "start_service",
            "status": "approved",
            "metadata": self._metadata(),
        }

    async def consume(self, approval_id):
        self.consume_calls.append(approval_id)
        return {
            "approval_id": approval_id,
            "incident_id": "incident-1",
            "action": "start_service",
            "status": "consumed",
            "metadata": self._metadata(),
        }

    async def cancel(self, approval_id, *, reason, metadata_patch=None):
        self.cancel_calls.append(
            (approval_id, reason, dict(metadata_patch or {}))
        )
        return {
            "approval_id": approval_id,
            "incident_id": "incident-1",
            "action": "start_service",
            "status": "rejected",
            "metadata": {
                **self._metadata(),
                "cancellation_reason": reason,
                **dict(metadata_patch or {}),
            },
        }


class FakeApprovalStore:
    def __init__(self):
        self.consume_calls = []

    @staticmethod
    def _metadata():
        return bind_metadata(
            {}, incident_id="incident-1", tool_name="ssh_vm", action="restart_service", target="vm01",
            parameters={}, timeout=30, runbook_id=None, runbook_version=None, rollback=False,
        )

    async def get(self, approval_id):
        return {"approval_id": approval_id, "incident_id": "incident-1", "action": "restart_service", "status": "approved", "metadata": self._metadata()}

    async def consume(self, approval_id):
        self.consume_calls.append(approval_id)
        return {"approval_id": approval_id, "incident_id": "incident-1", "action": "restart_service", "status": "consumed", "metadata": self._metadata()}


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
    memory_calls = 0
    end_calls = 0

    async def _execution_node(self, state):
        state["execution_result"] = {"success": False, "execution_blocked": False, "reason": "mcp_write_failed"}
        return state

    async def _verification_node(self, state):
        ExecutionFailsOrchestrator.verification_calls += 1
        raise AssertionError("verification must not run after failed execution")

    async def _memory_node(self, state):
        ExecutionFailsOrchestrator.memory_calls += 1
        state["operational_memory_writeback"] = {
            "memory_id": "failed-memory-1",
            "outcome_class": "failed_recovery",
        }
        return state

    async def _end_node(self, state):
        ExecutionFailsOrchestrator.end_calls += 1
        state["current_node"] = "end"
        return state


class VerificationFailsOrchestrator(FakeOrchestrator):
    async def _verification_node(self, state):
        state["verification_result"] = {"status": "failed", "message": "service still unhealthy"}
        return state


def _paused_state():
    return {
        "approval": {"approval_id": "approval-123", "status": "pending"},
        "execution_request": {"tool_name": "ssh_vm", "action": "restart_service", "target": "vm01"},
        "findings": [],
    }


def _guarded_paused_state():
    return {
        "approval": {"approval_id": "approval-guarded", "status": "pending"},
        "execution_request": {
            "tool_name": "ssh_vm",
            "action": "start_service",
            "target": "10.100.6.199",
            "parameters": {"service": "nginx", "target_port": 86},
            "timeout": 30,
            "runbook_id": "vm-service-recovery",
            "runbook_version": "1.1",
            "rollback": False,
        },
        "context": {},
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
async def test_resume_injects_consumed_approval_context_into_execution_request(monkeypatch):
    runtime = _runtime(_paused_state())
    FakeOrchestrator.verification_calls = 0
    monkeypatch.setattr(runtime_module, "E2EOrchestrator", FakeOrchestrator)

    result = await runtime.resume_after_approval("incident-1")

    assert result["current_node"] == "end"
    assert runtime.checkpoints.completed is not None
    assert runtime.checkpoints.failed is None
    assert runtime.approvals.consume_calls == ["approval-123"]
    request = FakeOrchestrator.captured_execution_request
    assert request["approval_granted"] is True
    assert request["approval_id"] == "approval-123"
    assert request["incident_id"] == "incident-1"
    assert FakeOrchestrator.verification_calls == 1
    assert runtime.incidents.statuses[-1] == ("incident-1", "resolved")


@pytest.mark.asyncio
async def test_failed_execution_is_learned_without_verification_or_resolution(monkeypatch):
    runtime = _runtime(_paused_state())
    ExecutionFailsOrchestrator.verification_calls = 0
    ExecutionFailsOrchestrator.memory_calls = 0
    ExecutionFailsOrchestrator.end_calls = 0
    monkeypatch.setattr(runtime_module, "E2EOrchestrator", ExecutionFailsOrchestrator)

    result = await runtime.resume_after_approval("incident-1")

    assert result["terminal_reason"] == "mcp_write_failed"
    assert result["operational_memory_writeback"]["outcome_class"] == "failed_recovery"
    assert runtime.checkpoints.failed is not None
    assert runtime.checkpoints.completed is None
    assert ExecutionFailsOrchestrator.verification_calls == 0
    assert ExecutionFailsOrchestrator.memory_calls == 1
    assert ExecutionFailsOrchestrator.end_calls == 1
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


@pytest.mark.asyncio
async def test_durable_runtime_revokes_stale_approval_before_consume(monkeypatch):
    runtime = _runtime(_guarded_paused_state())
    runtime.approvals = GuardedApprovalStore()

    async def snapshot(**kwargs):
        return {
            "read_success": True,
            "error": None,
            "evidence": [{"reference": "svc-active"}],
            "context": {"live_evidence": {"evidence": [{"reference": "svc-active"}]}},
        }

    monkeypatch.setattr(
        runtime_module.RunbookRuntimeGuard,
        "collect_snapshot",
        snapshot,
    )
    monkeypatch.setattr(
        runtime_module.RunbookRuntimeGuard,
        "preflight",
        lambda **kwargs: {
            "safe_to_execute": False,
            "reason": "service_no_longer_unhealthy",
            "evidence_refs": ["svc-active"],
        },
    )

    with pytest.raises(ValueError) as exc:
        await runtime.resume_after_approval("incident-1")

    assert str(exc.value) == (
        "approval_preflight_stale:service_no_longer_unhealthy"
    )
    assert runtime.approvals.consume_calls == []
    assert len(runtime.approvals.cancel_calls) == 1
    assert runtime.approvals.cancel_calls[0][0] == "approval-guarded"
    assert runtime.checkpoints.failed is not None
    failed_state = runtime.checkpoints.failed[1]
    assert failed_state["approval"]["status"] == "rejected"
    assert failed_state["execution_result"]["execution_blocked"] is True


@pytest.mark.asyncio
async def test_durable_runtime_keeps_retryable_approval_unconsumed(monkeypatch):
    runtime = _runtime(_guarded_paused_state())
    runtime.approvals = GuardedApprovalStore()

    async def snapshot(**kwargs):
        return {
            "read_success": False,
            "error": "vm_telemetry_unavailable",
            "evidence": [],
            "context": {"live_evidence": {"evidence": []}},
        }

    monkeypatch.setattr(
        runtime_module.RunbookRuntimeGuard,
        "collect_snapshot",
        snapshot,
    )
    monkeypatch.setattr(
        runtime_module.RunbookRuntimeGuard,
        "preflight",
        lambda **kwargs: {
            "safe_to_execute": False,
            "reason": "fresh_service_status_missing",
            "evidence_refs": [],
        },
    )

    with pytest.raises(ValueError) as exc:
        await runtime.resume_after_approval("incident-1")

    assert str(exc.value) == (
        "approval_preflight_retryable:fresh_service_status_missing"
    )
    assert runtime.approvals.consume_calls == []
    assert runtime.approvals.cancel_calls == []
    assert runtime.checkpoints.failed is None
