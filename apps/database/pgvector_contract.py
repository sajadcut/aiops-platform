from __future__ import annotations

from typing import Any, Dict

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession


async def validate_pgvector(session: AsyncSession, expected_dimension: int) -> Dict[str, Any]:
    """Validate pgvector strictly for Operational Memory, never Knowledge RAG."""
    extension = (await session.execute(text("SELECT extversion FROM pg_extension WHERE extname='vector'"))).scalar_one_or_none()
    if not extension:
        raise RuntimeError("pgvector_extension_missing")

    dimension = (await session.execute(text(
        """SELECT atttypmod FROM pg_attribute
        WHERE attrelid='memory_entries'::regclass
          AND attname='embedding' AND atttypid='vector'::regtype"""
    ))).scalar_one_or_none()
    if dimension is None:
        raise RuntimeError("memory_embedding_vector_column_missing")
    if int(dimension) != int(expected_dimension):
        raise RuntimeError(f"memory_embedding_dimension_mismatch:{dimension}!={expected_dimension}")

    return {
        "extension": extension,
        "dimension": int(dimension),
        "expected_dimension": int(expected_dimension),
        "scope": "operational_memory",
        "valid": True,
    }
