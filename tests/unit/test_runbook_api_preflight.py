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
        _Store.consume_calls += 1
        return {
            "approval_id": approval_id,
            "status": "consumed",
        }


@pytest.mark.asyncio
async def test_direct_runbook_preflight_blocks_before_approval_consume(monkeypatch):
    _Store.consume_calls = 0
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
    assert execute_calls == []
