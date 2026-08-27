import pytest
from fastapi import HTTPException

from apps.api import execution


class Identity:
    def __init__(self, roles=("sre",), subject="operator-1"):
        self.roles = roles
        self.subject = subject


class FakeDB:
    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False


class FakeStore:
    current = None
    last_patch = None
    last_status = None

    def __init__(self, _db):
        pass

    async def get(self, _approval_id):
        return dict(self.current) if self.current else None

    async def set_status(self, _approval_id, status, *, metadata_patch=None):
        self.__class__.last_status = status
        self.__class__.last_patch = dict(metadata_patch or {})
        result = dict(self.current)
        result["status"] = status
        result["metadata"] = {**(result.get("metadata") or {}), **self.last_patch}
        return result


@pytest.fixture(autouse=True)
def fake_dependencies(monkeypatch):
    FakeStore.current = {
        "approval_id": "a1",
        "incident_id": "i1",
        "action": "restart_service",
        "risk_level": "high",
        "status": "pending",
        "metadata": {"target": "vm01", "tool_name": "ssh_vm"},
    }
    FakeStore.last_patch = None
    FakeStore.last_status = None
    monkeypatch.setattr(execution, "AsyncSessionLocal", lambda: FakeDB())
    monkeypatch.setattr(execution, "PostgreSQLApprovalStore", FakeStore)

    async def no_audit(*_args, **_kwargs):
        return None

    monkeypatch.setattr(execution, "_audit_durable", no_audit)


@pytest.mark.asyncio
async def test_reject_requires_reason_before_db_transition():
    with pytest.raises(HTTPException) as exc:
        await execution.reject("a1", {}, Identity())
    assert exc.value.status_code == 400
    assert "reason" in str(exc.value.detail).lower()
    assert FakeStore.last_status is None


@pytest.mark.asyncio
async def test_reject_persists_reason_and_actor_metadata():
    result = await execution.reject("a1", {"reason": "change freeze window"}, Identity(subject="sre@example"))
    assert result["status"] == "rejected"
    assert FakeStore.last_status == "rejected"
    assert FakeStore.last_patch == {
        "rejection_reason": "change freeze window",
        "rejected_by": "sre@example",
    }


@pytest.mark.asyncio
async def test_stale_approval_cannot_be_approved_again():
    FakeStore.current["status"] = "approved"
    with pytest.raises(HTTPException) as exc:
        await execution.approve("a1", Identity())
    assert exc.value.status_code == 409
    assert FakeStore.last_status is None


@pytest.mark.asyncio
async def test_high_risk_approval_requires_sre_permission():
    with pytest.raises(HTTPException) as exc:
        await execution.approve("a1", Identity(roles=("operator",)))
    assert exc.value.status_code == 403
    assert FakeStore.last_status is None
