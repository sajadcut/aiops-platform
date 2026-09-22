from types import SimpleNamespace

import pytest
from fastapi import HTTPException

import apps.api.execution as api
from apps.execution_service import ExecutionResult


class _Session:
    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False


class _Store:
    consume_calls = 0

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

    async def consume(self, approval_id):
        self.__class__.consume_calls += 1
        return {
            "approval_id": approval_id,
            "incident_id": "incident-1",
            "action": "start_service",
            "status": "consumed",
            "metadata": {},
        }


class _Registry:
    def __init__(self, _root):
        pass

    def get(self, runbook_id):
        return {
            "id": runbook_id,
            "verification": {
                "checks": [
                    {
                        "state": "service_active",
                        "direction": "equals",
                        "expected": True,
                    }
                ]
            },
        }


def _payload(**overrides):
    value = {
        "tool_name": "ssh_vm",
        "action": "start_service",
        "target": "10.100.6.199",
        "parameters": {"service": "nginx", "target_port": 86},
        "incident_id": "incident-1",
        "approval_id": "approval-1",
        "timeout": 30,
    }
    value.update(overrides)
    return value


def _identity():
    return SimpleNamespace(subject="sre-user")


def test_direct_runtime_contract_fails_closed_for_unimplemented_write_tool():
    with pytest.raises(HTTPException) as exc:
        api._direct_runtime_contract(
            _payload(
                tool_name="kubernetes_mcp",
                action="restart_workload",
                parameters={"namespace": "prod"},
            )
        )

    assert exc.value.status_code == 409
    assert exc.value.detail == "direct_execution_runtime_contract_required"


@pytest.mark.asyncio
async def test_direct_execute_blocks_live_precondition_before_consume(monkeypatch):
    _Store.consume_calls = 0
    execute_calls = []

    monkeypatch.setattr(api, "AsyncSessionLocal", lambda: _Session())
    monkeypatch.setattr(api, "PostgreSQLApprovalStore", _Store)
    monkeypatch.setattr(
        api.tool_registry,
        "get_tool",
        lambda _name: SimpleNamespace(requires_approval=True),
    )
    monkeypatch.setattr(api, "_validate_approval_binding", lambda *_args: None)

    async def no_audit(*args, **kwargs):
        return None

    monkeypatch.setattr(api, "_audit_durable", no_audit)

    async def snapshot(**kwargs):
        return {
            "supported": True,
            "read_success": True,
            "error": None,
            "evidence": [],
            "context": {"live_evidence": {"evidence": []}},
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

    async def execute(_request):
        execute_calls.append(_request)
        raise AssertionError("execution must not run after failed preflight")

    monkeypatch.setattr(api.ExecutionService, "execute", execute)

    with pytest.raises(HTTPException) as exc:
        await api.execute(_payload(), identity=_identity())

    assert exc.value.status_code == 409
    assert exc.value.detail == (
        "direct_execution_precondition_failed:service_no_longer_unhealthy"
    )
    assert _Store.consume_calls == 0
    assert execute_calls == []


@pytest.mark.asyncio
async def test_direct_execute_returns_verified_only_after_post_action_verification(monkeypatch):
    _Store.consume_calls = 0
    snapshots = []

    monkeypatch.setattr(api, "AsyncSessionLocal", lambda: _Session())
    monkeypatch.setattr(api, "PostgreSQLApprovalStore", _Store)
    monkeypatch.setattr(
        api.tool_registry,
        "get_tool",
        lambda _name: SimpleNamespace(requires_approval=True),
    )
    monkeypatch.setattr(api, "_validate_approval_binding", lambda *_args: None)
    monkeypatch.setattr(api, "RunbookRegistry", _Registry)

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

    monkeypatch.setattr(
        api.RunbookRuntimeGuard,
        "collect_snapshot",
        snapshot,
    )
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

    memory_calls = []

    async def record_memory(_db, **kwargs):
        memory_calls.append(kwargs)
        return "memory-direct-1"

    monkeypatch.setattr(api, "record_runbook_outcome", record_memory)

    async def execute(request):
        return ExecutionResult(
            success=True,
            tool_name=request.tool_name,
            action=request.action,
            target=request.target,
            result={"success": True},
            approval_id=request.approval_id,
        )

    monkeypatch.setattr(api.ExecutionService, "execute", execute)

    result = await api.execute(_payload(), identity=_identity())

    assert _Store.consume_calls == 1
    assert snapshots == ["pre", "post"]
    assert result["success"] is True
    assert result["verified"] is True
    assert result["verification"]["status"] == "success"
    assert result["precondition"]["safe_to_execute"] is True
    assert result["operational_memory_writeback"]["memory_id"] == "memory-direct-1"
    assert len(memory_calls) == 1
    assert memory_calls[0]["incident_id"] == "incident-1"
    assert memory_calls[0]["action"] == "start_service"
