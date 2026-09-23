from __future__ import annotations

from fastapi import HTTPException

from database.migration_validation import validate_migration_head
from domain.contracts.config import settings
from domain.contracts.logging import logger


async def require_database_ready(db, *, operation: str) -> None:
    """Fail closed when an API operation depends on a stale database schema.

    Development may boot with migration drift for diagnostics, but API paths that
    depend on current ORM/schema contracts must not execute against missing
    columns and leak database programming errors.
    """
    if not settings.DATABASE_VALIDATE_MIGRATIONS_ON_STARTUP:
        return

    migration = await validate_migration_head(db)
    if migration.get("valid"):
        return

    logger.error(
        "api_operation_blocked_by_migration_drift",
        operation=operation,
        migration=migration,
    )
    raise HTTPException(
        status_code=503,
        detail={
            "code": "DATABASE_MIGRATION_DRIFT",
            "message": "Database schema is not at the repository Alembic head",
            "expected_heads": migration.get("expected_heads", []),
            "current_heads": migration.get("current_heads", []),
            "error": migration.get("error"),
        },
    )
