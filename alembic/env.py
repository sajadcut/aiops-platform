from logging.config import fileConfig
from sqlalchemy import create_engine, pool
from alembic import context
import sys
from pathlib import Path

# اضافه کردن مسیر ریشه پروژه به PYTHONPATH
sys.path.insert(0, str(Path(__file__).parent.parent))

# import مدل‌های ما
from app.infrastructure.database import Base
from app.domain.models import Incident, Evidence, Finding, KnowledgeDocument, MemoryEntry

# این خط تنظیمات alembic.ini را می‌خواند
config = context.config

# تنظیم لاگینگ
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# metadata مدل‌های ما
target_metadata = Base.metadata

def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode."""
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )

    with context.begin_transaction():
        context.run_migrations()

def run_migrations_online() -> None:
    """Run migrations in 'online' mode (Sync Engine)."""
    # استفاده از create_engine معمولی (همزمان)
    connectable = create_engine(
        config.get_main_option("sqlalchemy.url"),
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata
        )

        with context.begin_transaction():
            context.run_migrations()

if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()