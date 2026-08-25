from logging.config import fileConfig
import os
from pathlib import Path

from alembic import context
from sqlalchemy import create_engine, pool

PROJECT_ROOT = Path(__file__).resolve().parents[2]
import sys
sys.path.insert(0, str(PROJECT_ROOT))

from database import Base
from domain.models import Incident, Evidence, Finding, KnowledgeDocument, MemoryEntry  # noqa: F401

config = context.config
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

raw_database_url = os.getenv("ALEMBIC_DATABASE_URL") or os.getenv("DATABASE_URL") or config.get_main_option("sqlalchemy.url")
if raw_database_url.startswith("postgresql+asyncpg://"):
    database_url = raw_database_url.replace("postgresql+asyncpg://", "postgresql+psycopg://", 1)
else:
    database_url = raw_database_url
config.set_main_option("sqlalchemy.url", database_url)
target_metadata = Base.metadata


def run_migrations_offline() -> None:
    context.configure(
        url=database_url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    connectable = create_engine(database_url, poolclass=pool.NullPool)
    with connectable.connect() as connection:
        context.configure(connection=connection, target_metadata=target_metadata)
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
