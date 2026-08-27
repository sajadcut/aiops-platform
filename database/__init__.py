"""اتصال مرکزی async به PostgreSQL و factory مشترک sessionها.

تمام repository/storeهای runtime باید از همین engine/sessionmaker استفاده کنند تا pool،
health check و تنظیمات DB یک‌جا کنترل شوند. Migrationها engine جداگانه Alembic دارند اما
به همان قرارداد `.env` متصل‌اند.
"""

from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
from sqlalchemy.orm import declarative_base
from sqlalchemy import text
from domain.contracts.config import settings
from domain.contracts.logging import logger

# تمام ORM modelها از این Base مشتق می‌شوند؛ Alembic metadata همین graph مدل را می‌بیند.
Base = declarative_base()

engine = create_async_engine(
    settings.DATABASE_URL,
    echo=settings.DEBUG,
    pool_size=settings.DATABASE_POOL_SIZE,
    max_overflow=settings.DATABASE_MAX_OVERFLOW,
    # اتصال stale قبل از تحویل از pool بررسی می‌شود تا request به connection مرده نخورد.
    pool_pre_ping=True,
)

AsyncSessionLocal = async_sessionmaker(
    engine, class_=AsyncSession, expire_on_commit=False
)


async def get_db() -> AsyncSession:
    """Dependency ساده FastAPI که عمر session را به request محدود می‌کند."""
    async with AsyncSessionLocal() as session:
        yield session


async def check_pgvector_ready() -> dict:
    """Connectivity و وجود extension pgvector را برای health/readiness بررسی می‌کند."""
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
                logger.info(f"pgvector extension found, version: {version}")
            else:
                # نبود extension با DB-down فرق دارد؛ health endpoint این دو failure mode
                # را جدا گزارش می‌کند تا نبود vector به‌اشتباه healthy تلقی نشود.
                logger.warning("pgvector extension not found in PostgreSQL")

    except Exception as e:
        error_msg = str(e)
        result["error"] = error_msg
        logger.warning(f"Database not available: {error_msg}")

    return result
