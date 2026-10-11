"""Read-only local database revision preflight for Windows start-all.ps1.

Deliberately does not run Alembic upgrades, stamps, downgrades, or writes.
A recoverable DB backup and explicit operator decision precede schema changes.
"""
from __future__ import annotations

import asyncio

from database import AsyncSessionLocal
from database.migration_validation import validate_migration_head


async def inspect_migrations() -> dict:
    async with AsyncSessionLocal() as db:
        return await validate_migration_head(db)


def migration_preflight_result(result: dict) -> int:
    """Return 0 for matching heads, 3 for schema drift; print no credentials."""
    if result.get("valid"):
        print("DATABASE_MIGRATION_OK")
        return 0
    current = ", ".join(str(v) for v in result.get("current_heads") or []) or "unknown"
    expected = ", ".join(str(v) for v in result.get("expected_heads") or []) or "unknown"
    print("DATABASE_MIGRATION_DRIFT")
    print(f"  Current database head(s): {current}")
    print(f"  Required repository head(s): {expected}")
    if result.get("error"):
        print(f"  Validation error: {result['error']}")
    print("  AIOps API is not safe to start against this database schema.")
    print("  STOP the application, take a verified database backup, and then run:")
    print("    .\\.venv\\Scripts\\python.exe -m alembic -c database/migrations/alembic.ini upgrade head")
    print("  Verify with:")
    print("    .\\.venv\\Scripts\\python.exe -m alembic -c database/migrations/alembic.ini current")
    print("  Do not use 'alembic stamp head' or disable migration validation.")
    return 3


def main() -> int:
    try:
        migration = asyncio.run(inspect_migrations())
    except Exception as exc:
        # Avoid exposing DB URLs, passwords and driver exception messages.
        print("DATABASE_PREFLIGHT_UNAVAILABLE")
        print(f"  Validation failed: {type(exc).__name__}")
        print("  Check DATABASE_URL, PostgreSQL connectivity and DB permissions.")
        return 4
    return migration_preflight_result(migration)


if __name__ == "__main__":
    raise SystemExit(main())
