from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
from sqlalchemy.orm import declarative_base
from sqlalchemy import text
from app.core.config import settings
from app.core.logging import logger

Base = declarative_base()

engine = create_async_engine(
    settings.DATABASE_URL,
    echo=settings.DEBUG,
    pool_size=settings.DATABASE_POOL_SIZE,
    max_overflow=settings.DATABASE_MAX_OVERFLOW,
    pool_pre_ping=True,
)

AsyncSessionLocal = async_sessionmaker(
    engine, class_=AsyncSession, expire_on_commit=False
)

async def get_db() -> AsyncSession:
    async with AsyncSessionLocal() as session:
        yield session

async def check_pgvector_ready() -> dict:
    result = {
        "db_connected": False,
        "pgvector_available": False,
        "error": None
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
                logger.warning("pgvector extension not found in PostgreSQL")
                
    except Exception as e:
        error_msg = str(e)
        result["error"] = error_msg
        logger.warning(f"Database not available: {error_msg}")
        
    return result