from __future__ import annotations

from pathlib import Path
from typing import Any

from alembic.config import Config
from alembic.script import ScriptDirectory
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession


def expected_migration_heads() -> set[str]:
    ini = Path(__file__).resolve().parent / "migrations" / "alembic.ini"
    config = Config(str(ini))
    script = ScriptDirectory.from_config(config)
    return set(script.get_heads())


async def validate_migration_head(session: AsyncSession) -> dict[str, Any]:
    """Compare the database's applied Alembic revision(s) with repository HEAD(s)."""
    expected = expected_migration_heads()
    try:
        rows = await session.execute(text("SELECT version_num FROM alembic_version"))
        current = {str(row[0]) for row in rows.fetchall()}
    except Exception as exc:
        return {
            "valid": False,
            "expected_heads": sorted(expected),
            "current_heads": [],
            "error": type(exc).__name__,
        }
    return {
        "valid": current == expected,
        "expected_heads": sorted(expected),
        "current_heads": sorted(current),
        "error": None,
    }
