"""اتصال مرکزی async به PostgreSQL و factory مشترک sessionها.

تمام repository/storeهای runtime باید از همین engine/sessionmaker استفاده کنند تا pool،
health check و تنظیمات DB یک‌جا کنترل شوند. Migrationها engine جداگانه Alembic دارند اما
به همان قرارداد runtime متصل‌اند.
"""

import json
from datetime import date, datetime, time
from decimal import Decimal
from enum import Enum
from uuid import UUID

from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
from sqlalchemy.orm import declarative_base
from sqlalchemy import text
from domain.contracts.config import settings
from domain.contracts.logging import logger

Base = declarative_base()


def _json_default(value):
    if isinstance(value, (datetime, date, time)):
        return value.isoformat()
    if isinstance(value, UUID):
        return str(value)
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, Decimal):
        return float(value)
    model_dump = getattr(value, "model_dump", None)
    if callable(model_dump):
        return model_dump(mode="json")
    raise TypeError(f"Object of type {type(value).__name__} is not JSON serializable")


def _json_serializer(value) -> str:
    return json.dumps(value, ensure_ascii=False, default=_json_default)


engine = create_async_engine(
    settings.DATABASE_URL,
    echo=settings.DEBUG,
    pool_size=settings.DATABASE_POOL_SIZE,
    max_overflow=settings.DATABASE_MAX_OVERFLOW,
    pool_pre_ping=True,
    json_serializer=_json_serializer,
)

AsyncSessionLocal = async_sessionmaker(
    engine, class_=AsyncSession, expire_on_commit=False
)


async def get_db() -> AsyncSession:
    async with AsyncSessionLocal() as session:
        yield session


async def check_pgvector_ready() -> dict:
    """Connectivity و وجود extension pgvector را بدون افشای DSN/error text بررسی می‌کند."""
    result = {
        "db_connected": False,
        "pgvector_available": False,
        "error": None,
    }
    try:
        async with AsyncSessionLocal() as session:
            await session.execute(text("SELECT 1"))
            result["db_connected"] = True

            query = text("SELECT extversion FROM pg_extension WHERE extname = 'vector'")
            pg_row = await session.execute(query)
            version = pg_row.scalar()

            if version:
                result["pgvector_available"] = True
                logger.info("pgvector_extension_found", version=str(version))
            else:
                logger.warning("pgvector_extension_not_found")

    except Exception as exc:
        result["error"] = type(exc).__name__
        logger.exception("database_pgvector_probe_failed")

    return result
