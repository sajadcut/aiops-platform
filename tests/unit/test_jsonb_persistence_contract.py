from datetime import datetime
import json

import pytest

from apps.approval_service.postgres import PostgreSQLApprovalStore
from apps.audit_service.postgres import PostgreSQLAuditStore


class FakeResult:
    def mappings(self):
        return self

    def first(self):
        return None


class FakeSession:
    def __init__(self):
        self.calls = []
        self.commits = 0

    async def execute(self, statement, params=None):
        self.calls.append((str(statement), params))
        return FakeResult()

    async def commit(self):
        self.commits += 1


@pytest.mark.asyncio
async def test_approval_metadata_and_timestamps_are_normalized_before_postgres_bind():
    session = FakeSession()
    store = PostgreSQLApprovalStore(session)
    record = {
        "approval_id": "a1",
        "incident_id": "i1",
        "action": "restart_service",
        "risk_level": "high",
        "approver": "lead",
        "status": "pending",
        "metadata": {"target": "vm01"},
        "created_at": "2026-01-01T00:00:00+00:00",
        "approved_at": None,
        "rejected_at": None,
    }
    await store.save(record)
    insert_call = next(call for call in session.calls if "INSERT INTO approvals" in call[0])
    params = insert_call[1]
    assert isinstance(params["metadata"], str)
    assert json.loads(params["metadata"]) == {"target": "vm01"}
    assert isinstance(params["created_at"], datetime)
    assert params["created_at"].tzinfo is not None
    assert params["created_at"].utcoffset().total_seconds() == 0
    assert params["approved_at"] is None
    assert params["rejected_at"] is None


@pytest.mark.asyncio
async def test_audit_metadata_and_timestamp_are_normalized_before_postgres_bind():
    session = FakeSession()
    store = PostgreSQLAuditStore(session)
    event = {
        "event_id": "e1",
        "event_type": "execution",
        "actor": "test",
        "incident_id": "i1",
        "action": "restart_service",
        "status": "recorded",
        "metadata": {"approval_id": "a1"},
        "created_at": "2026-01-01T00:00:00+00:00",
    }
    await store.append(event)
    params = session.calls[0][1]
    assert isinstance(params["metadata"], str)
    assert json.loads(params["metadata"]) == {"approval_id": "a1"}
    assert isinstance(params["created_at"], datetime)
    assert params["created_at"].tzinfo is not None
    assert params["created_at"].utcoffset().total_seconds() == 0
