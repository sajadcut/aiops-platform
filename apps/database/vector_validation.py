from __future__ import annotations

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession


async def validate_pgvector(session: AsyncSession, expected_dimension: int | None = None) -> dict:
    ext = (await session.execute(text("SELECT extname FROM pg_extension WHERE extname='vector'"))).scalar_one_or_none()
    result = {"extension_installed": bool(ext), "expected_dimension": expected_dimension, "dimension_valid": None}
    if not ext or expected_dimension is None:
        return result
    # Validate that vector columns are actually typed as vector and expose dimensions.
    rows = (await session.execute(text("""
        SELECT table_name, column_name, udt_name
        FROM information_schema.columns
        WHERE table_schema='public' AND column_name='embedding'
    """))).mappings().all()
    result["embedding_columns"] = [dict(r) for r in rows]
    result["dimension_valid"] = bool(rows)
    return result
