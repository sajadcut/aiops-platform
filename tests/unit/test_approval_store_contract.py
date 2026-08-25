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
        if "UPDATE approvals SET status" in sql and params:
            self.row = {"approval_id": params.get("id", "a1"), "status": params.get("status", "approved")}
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
async def test_approval_store_status_update_uses_durable_sql():
    session = FakeSession()
    session.row = {
        "approval_id": "a1",
        "status": "pending",
    }
    store = PostgreSQLApprovalStore(session)
    result = await store.set_status("a1", "approved")
    assert result["status"] == "approved"
    assert any("UPDATE approvals SET status" in call[0] for call in session.calls)
