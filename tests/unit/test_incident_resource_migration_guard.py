import pytest
from fastapi import HTTPException

import apps.api.dashboard as dashboard
import apps.api.database_guard as database_guard
import apps.api.incident_resources as incident_resources
import apps.api.signals as signals
from domain.contracts.config import settings


@pytest.mark.asyncio
async def test_shared_migration_guard_returns_controlled_503(monkeypatch):
    monkeypatch.setattr(settings, "DATABASE_VALIDATE_MIGRATIONS_ON_STARTUP", True)

    async def stale_schema(_db):
        return {
            "valid": False,
            "expected_heads": ["j7g8h9i0j1k2"],
            "current_heads": ["g4d5e6f7a8b9"],
            "error": None,
        }

    monkeypatch.setattr(database_guard, "validate_migration_head", stale_schema)

    with pytest.raises(HTTPException) as exc_info:
        await database_guard.require_database_ready(
            object(),
            operation="memory_test",
        )

    exc = exc_info.value
    assert exc.status_code == 503
    assert exc.detail["code"] == "DATABASE_MIGRATION_DRIFT"
    assert exc.detail["expected_heads"] == ["j7g8h9i0j1k2"]
    assert exc.detail["current_heads"] == ["g4d5e6f7a8b9"]


@pytest.mark.asyncio
async def test_shared_migration_guard_can_be_disabled(monkeypatch):
    monkeypatch.setattr(settings, "DATABASE_VALIDATE_MIGRATIONS_ON_STARTUP", False)

    async def should_not_run(_db):
        raise AssertionError("migration validation must not run when disabled")

    monkeypatch.setattr(database_guard, "validate_migration_head", should_not_run)

    await database_guard.require_database_ready(
        object(),
        operation="disabled_test",
    )


@pytest.mark.asyncio
async def test_signal_and_memory_resources_use_shared_guard(monkeypatch):
    calls = []

    async def capture(_db, *, operation):
        calls.append(operation)

    monkeypatch.setattr(signals, "require_database_ready", capture)
    monkeypatch.setattr(incident_resources, "require_database_ready", capture)

    await signals._require_database_ready(object())
    await incident_resources._require_current_database_schema(object())

    assert calls == ["signal_ingestion", "incident_memory_resource"]


@pytest.mark.asyncio
async def test_dashboard_summary_preserves_migration_drift_contract(monkeypatch):
    class FakeSessionContext:
        async def __aenter__(self):
            return object()

        async def __aexit__(self, exc_type, exc, tb):
            return False

    async def drift(_db, *, operation):
        assert operation == "dashboard_summary"
        raise HTTPException(
            status_code=503,
            detail={
                "code": "DATABASE_MIGRATION_DRIFT",
                "expected_heads": ["j7g8h9i0j1k2"],
                "current_heads": ["g4d5e6f7a8b9"],
            },
        )

    monkeypatch.setattr(dashboard, "AsyncSessionLocal", lambda: FakeSessionContext())
    monkeypatch.setattr(dashboard, "require_database_ready", drift)

    with pytest.raises(HTTPException) as exc_info:
        await dashboard.dashboard_summary(_identity={"sub": "test"})

    assert exc_info.value.status_code == 503
    assert exc_info.value.detail["code"] == "DATABASE_MIGRATION_DRIFT"
