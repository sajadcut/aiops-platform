from types import SimpleNamespace

import pytest
from fastapi import HTTPException

import apps.api.runbook_execution as api


class _Session:
    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False


class _Store:
    consume_calls = 0
    cancel_calls = 0

    def __init__(self, _db):
        pass

    async def get(self, approval_id):
        return {
            "approval_id": approval_id,
            "incident_id": "incident-1",
            "action": "start_service",
            "status": "approved",
            "metadata": {},
        }

    async def cancel(self, approval_id, *, reason, metadata_patch=None):
        _Store.cancel_calls += 1
        return {
            "approval_id": approval_id,
            "status": "rejected",
            "metadata": {
                "cancellation_reason": reason,
                **dict(metadata_patch or {}),
            },
        }

    async def consume(self, approval_id, *, issue_claim=False):
        _Store.consume_calls += 1
        return {
            "approval_id": approval_id,
            "status": "consumed",
            "_execution_claim": "test-claim" if issue_claim else None,
        }


@pytest.mark.asyncio
async def test_direct_runbook_preflight_blocks_before_approval_consume(monkeypatch):
    _Store.consume_calls = 0
    _Store.cancel_calls = 0
    execute_calls = []

    monkeypatch.setattr(api, "AsyncSessionLocal", lambda: _Session())
    monkeypatch.setattr(api, "PostgreSQLApprovalStore", _Store)
    monkeypatch.setattr(api, "assert_bound", lambda *args, **kwargs: None)

    async def no_audit(*args, **kwargs):
        return None

    monkeypatch.setattr(api, "_audit_durable", no_audit)

    async def snapshot(**kwargs):
        return {
            "supported": True,
            "read_success": True,
            "error": None,
            "context": {"live_evidence": {"evidence": []}},
            "evidence": [],
        }

    monkeypatch.setattr(
        api.RunbookRuntimeGuard,
        "collect_snapshot",
        snapshot,
    )
    monkeypatch.setattr(
        api.RunbookRuntimeGuard,
        "preflight",
        lambda **kwargs: {
            "safe_to_execute": False,
            "reason": "service_no_longer_unhealthy",
            "evidence_refs": ["svc"],
        },
    )

    async def execute(*args, **kwargs):
        execute_calls.append((args, kwargs))
        raise AssertionError("execution must not run after failed preflight")

    monkeypatch.setattr(api._executor, "execute", execute)

    payload = {
        "approval_id": "approval-1",
        "incident_id": "incident-1",
        "action": "start_service",
        "target": "10.100.6.199",
        "parameters": {
            "service": "nginx",
            "target_port": 86,
        },
    }

    with pytest.raises(HTTPException) as exc:
        await api.execute_runbook(
            "vm-service-recovery",
            payload,
            identity=SimpleNamespace(subject="sre-user"),
        )

    assert exc.value.status_code == 409
    assert exc.value.detail == (
        "runbook_execution_precondition_failed:"
        "service_no_longer_unhealthy"
    )
    assert _Store.consume_calls == 0
    assert _Store.cancel_calls == 1
    assert execute_calls == []


def test_non_executable_runbook_cannot_reach_production_execute(monkeypatch):
    monkeypatch.setattr(
        api._registry,
        "get",
        lambda runbook_id: {
            "id": runbook_id,
            "version": "1.0",
            "timeout": 30,
            "action": "observe_only",
        },
    )
    monkeypatch.setattr(
        api._registry,
        "validate",
        lambda runbook_id, parameters: {"valid": True},
    )

    with pytest.raises(HTTPException) as exc:
        api._runbook_contract(
            "descriptive-only",
            {
                "target": "vm01",
                "tool_name": "ssh_vm",
                "parameters": {},
            },
            require_executable=True,
        )

    assert exc.value.status_code == 409
    assert exc.value.detail == "runbook_not_executable"


def test_non_executable_runbook_remains_available_for_dry_run_contract_resolution(monkeypatch):
    monkeypatch.setattr(
        api._registry,
        "get",
        lambda runbook_id: {
            "id": runbook_id,
            "version": "1.0",
            "timeout": 30,
            "action": "observe_only",
        },
    )
    monkeypatch.setattr(
        api._registry,
        "validate",
        lambda runbook_id, parameters: {"valid": True},
    )

    runbook, tool, action, target, parameters, timeout, rollback = api._runbook_contract(
        "descriptive-only",
        {
            "target": "vm01",
            "tool_name": "mock_executor",
            "parameters": {},
        },
        require_executable=False,
    )

    assert runbook["id"] == "descriptive-only"
    assert tool == "mock_executor"
    assert action == "observe_only"
    assert target == "vm01"
    assert timeout == 30
    assert rollback is False


class _IncidentRepo:
    calls = []

    def __init__(self, _db):
        pass

    async def record_operational_outcome(self, incident_id, **kwargs):
        self.__class__.calls.append((incident_id, kwargs))
        return "resolved" if kwargs.get("verified") else "escalated"

    async def commit(self):
        return None


@pytest.mark.asyncio
async def test_runbook_success_verifies_learns_and_finalizes_incident(monkeypatch):
    _Store.consume_calls = 0
    _IncidentRepo.calls = []
    snapshots = []
    memory_calls = []

    monkeypatch.setattr(api, "AsyncSessionLocal", lambda: _Session())
    monkeypatch.setattr(api, "PostgreSQLApprovalStore", _Store)
    monkeypatch.setattr(api, "assert_bound", lambda *args, **kwargs: None)
    monkeypatch.setattr(api, "IncidentRepository", _IncidentRepo)

    async def no_audit(*args, **kwargs):
        return None

    monkeypatch.setattr(api, "_audit_durable", no_audit)

    async def snapshot(**kwargs):
        snapshots.append(kwargs["phase"])
        return {
            "supported": True,
            "read_success": True,
            "error": None,
            "evidence": [{"reference": f"{kwargs['phase']}-svc"}],
            "context": {
                "live_evidence": {
                    "evidence": [{"reference": f"{kwargs['phase']}-svc"}]
                }
            },
        }

    monkeypatch.setattr(api.RunbookRuntimeGuard, "collect_snapshot", snapshot)
    monkeypatch.setattr(
        api.RunbookRuntimeGuard,
        "preflight",
        lambda **kwargs: {
            "safe_to_execute": True,
            "reason": "fresh_execution_preconditions_satisfied",
            "evidence_refs": ["pre-svc"],
        },
    )

    verification = SimpleNamespace(
        status=SimpleNamespace(value="success"),
        required_objectives_met=True,
        model_dump=lambda mode=None: {
            "status": "success",
            "required_objectives_met": True,
            "evidence_refs": ["post-svc"],
        },
    )

    async def verify(**kwargs):
        return verification

    monkeypatch.setattr(api.RunbookRuntimeGuard, "verify", verify)

    async def execute(*args, **kwargs):
        return {
            "status": "executed",
            "fingerprint": "fp-1",
            "result": {
                "success": True,
                "tool_name": "ssh_vm",
                "action": "start_service",
                "target": "10.100.6.199",
            },
        }

    monkeypatch.setattr(api._executor, "execute", execute)

    async def record_memory(_db, **kwargs):
        memory_calls.append(kwargs)
        return "memory-runbook-1"

    monkeypatch.setattr(api, "record_runbook_outcome", record_memory)

    result = await api.execute_runbook(
        "vm-service-recovery",
        {
            "approval_id": "approval-1",
            "incident_id": "incident-1",
            "action": "start_service",
            "target": "10.100.6.199",
            "parameters": {
                "service": "nginx",
                "target_port": 86,
            },
        },
        identity=SimpleNamespace(subject="sre-user"),
    )

    assert _Store.consume_calls == 1
    assert snapshots == ["pre", "post"]
    assert result["verified"] is True
    assert result["verification"]["status"] == "success"
    assert result["operational_memory_writeback"]["memory_id"] == "memory-runbook-1"
    assert result["incident_status"] == "resolved"
    assert len(memory_calls) == 1
    assert len(_IncidentRepo.calls) == 1
    assert _IncidentRepo.calls[0][0] == "incident-1"
    assert _IncidentRepo.calls[0][1]["verified"] is True
    assert _IncidentRepo.calls[0][1]["memory_id"] == "memory-runbook-1"
