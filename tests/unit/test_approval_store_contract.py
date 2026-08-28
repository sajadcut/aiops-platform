from datetime import datetime, timezone

import pytest

from apps.approval_service.postgres import PostgreSQLApprovalStore


class Result:
    def __init__(self, row=None):
        self._row = row

    def mappings(self):
        return self

    def first(self):
        return self._row


class FakeSession:
    def __init__(self):
        self.calls = []
        self.row = None

    async def execute(self, statement, params=None):
        sql = str(statement)
        self.calls.append((sql, params))
        if "UPDATE approvals" in sql and "SET status=:status" in sql and params:
            self.row = {
                "approval_id": params.get("id", "a1"),
                "status": params.get("status", "approved"),
                "metadata": {"rejection_reason": "operator rejected"} if params.get("status") == "rejected" else {},
            }
        return Result(self.row)

    async def commit(self):
        self.calls.append(("commit", None))


@pytest.mark.asyncio
async def test_approval_store_reads_missing_record_as_none():
    session = FakeSession()
    store = PostgreSQLApprovalStore(session)
    assert await store.get("missing") is None
    assert session.calls


@pytest.mark.asyncio
async def test_approval_store_status_update_uses_atomic_durable_sql():
    session = FakeSession()
    session.row = {"approval_id": "a1", "status": "pending", "metadata": {}}
    store = PostgreSQLApprovalStore(session)
    result = await store.set_status("a1", "approved", metadata_patch={"approved_by": "operator"})
    assert result["status"] == "approved"
    sql_calls = [call for call in session.calls if "UPDATE approvals" in call[0] and "SET status=:status" in call[0]]
    assert sql_calls
    assert "status='pending'" in sql_calls[-1][0]
    assert "metadata=COALESCE" in sql_calls[-1][0]


@pytest.mark.asyncio
async def test_approval_store_rejection_can_persist_reason_metadata():
    session = FakeSession()
    session.row = {"approval_id": "a1", "status": "pending", "metadata": {}}
    store = PostgreSQLApprovalStore(session)
    result = await store.set_status(
        "a1",
        "rejected",
        metadata_patch={"rejection_reason": "operator rejected", "rejected_by": "operator"},
    )
    assert result["status"] == "rejected"
    update = [call for call in session.calls if "UPDATE approvals" in call[0] and "SET status=:status" in call[0]][-1]
    assert "rejection_reason" in update[1]["metadata_patch"]


@pytest.mark.asyncio
async def test_approval_store_save_normalizes_iso_timestamps_for_asyncpg():
    session = FakeSession()
    store = PostgreSQLApprovalStore(session)
    created_at = "2026-08-28T10:25:28.742174+00:00"

    await store.save(
        {
            "approval_id": "a1",
            "incident_id": "i1",
            "action": "restart_service",
            "risk_level": "high",
            "approver": "Team-Lead",
            "status": "pending",
            "metadata": {"tool_name": "ssh_vm"},
            "created_at": created_at,
            "approved_at": None,
            "rejected_at": None,
        }
    )

    insert = [call for call in session.calls if "INSERT INTO approvals" in call[0]][0]
    assert isinstance(insert[1]["created_at"], datetime)
    assert insert[1]["created_at"] == datetime.fromisoformat(created_at)
    assert insert[1]["approved_at"] is None
    assert insert[1]["rejected_at"] is None


def test_approval_store_timestamp_normalizer_preserves_datetime_values():
    value = datetime(2026, 8, 28, 10, 25, tzinfo=timezone.utc)
    assert PostgreSQLApprovalStore._as_datetime(value) is value


def test_approval_store_timestamp_normalizer_rejects_invalid_types():
    with pytest.raises(TypeError, match="invalid_approval_timestamp_type:int"):
        PostgreSQLApprovalStore._as_datetime(123)
