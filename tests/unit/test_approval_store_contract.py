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
