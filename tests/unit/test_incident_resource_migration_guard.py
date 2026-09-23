import inspect

import pytest
from fastapi import HTTPException

import apps.api.incident_resources as incident_resources
from domain.contracts.config import settings


@pytest.mark.asyncio
async def test_incident_resource_migration_guard_returns_controlled_503(monkeypatch):
    monkeypatch.setattr(settings, "DATABASE_VALIDATE_MIGRATIONS_ON_STARTUP", True)

    async def stale_schema(_db):
        return {
            "valid": False,
            "expected_heads": ["j7g8h9i0j1k2"],
            "current_heads": ["g4d5e6f7a8b9"],
            "error": None,
        }

    monkeypatch.setattr(
        incident_resources,
        "validate_migration_head",
        stale_schema,
    )

    with pytest.raises(HTTPException) as exc_info:
        await incident_resources._require_current_database_schema(object())

    exc = exc_info.value
    assert exc.status_code == 503
    assert exc.detail["code"] == "DATABASE_MIGRATION_DRIFT"
    assert exc.detail["expected_heads"] == ["j7g8h9i0j1k2"]
    assert exc.detail["current_heads"] == ["g4d5e6f7a8b9"]


@pytest.mark.asyncio
async def test_incident_resource_migration_guard_can_be_disabled(monkeypatch):
    monkeypatch.setattr(settings, "DATABASE_VALIDATE_MIGRATIONS_ON_STARTUP", False)

    async def should_not_run(_db):
        raise AssertionError("migration validation must not run when disabled")

    monkeypatch.setattr(
        incident_resources,
        "validate_migration_head",
        should_not_run,
    )

    await incident_resources._require_current_database_schema(object())


def test_memory_dependent_incident_resources_are_guarded_against_schema_drift():
    for endpoint in (
        incident_resources.get_memory,
        incident_resources.get_memory_health,
        incident_resources.get_memory_summary,
        incident_resources.invalidate_memory,
        incident_resources.validate_memory,
        incident_resources.get_operator_summary,
    ):
        assert "_require_current_database_schema" in inspect.getsource(endpoint)
