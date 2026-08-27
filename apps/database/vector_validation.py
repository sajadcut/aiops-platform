from __future__ import annotations

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession


async def validate_pgvector(session: AsyncSession, expected_dimension: int | None = None) -> dict:
    ext = (await session.execute(text("SELECT extversion FROM pg_extension WHERE extname='vector'"))).scalar_one_or_none()
    result = {"extension_installed": bool(ext), "extension_version": ext, "expected_dimension": expected_dimension, "dimension_valid": None}
    if not ext:
        return result
    rows = (await session.execute(text("""
        SELECT table_name, column_name,
               CASE WHEN udt_name='vector' THEN atttypmod ELSE NULL END AS dimension
        FROM information_schema.columns c
        LEFT JOIN pg_attribute a
          ON a.attrelid = format('%I.%I', c.table_schema, c.table_name)::regclass
         AND a.attname = c.column_name
        WHERE c.table_schema='public' AND c.column_name='embedding'
    """))).mappings().all()
    result["embedding_columns"] = [dict(r) for r in rows]
    if expected_dimension is None:
        result["dimension_valid"] = bool(rows)
    else:
        dimensions = [r.get("dimension") for r in rows if r.get("dimension") is not None]
        result["dimension_valid"] = bool(dimensions) and all(int(d) == int(expected_dimension) for d in dimensions)
    return result
