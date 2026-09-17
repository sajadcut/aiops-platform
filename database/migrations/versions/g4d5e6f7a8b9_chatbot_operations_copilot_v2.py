"""Operations Copilot v2 session metadata.

Revision ID: g4d5e6f7a8b9
Revises: f3c4d5e6f7a8
"""
from typing import Sequence, Union

from alembic import op

revision: str = "g4d5e6f7a8b9"
down_revision: Union[str, Sequence[str], None] = "f3c4d5e6f7a8"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute("ALTER TABLE chat_sessions ADD COLUMN IF NOT EXISTS title VARCHAR(160) NULL")
    op.execute("ALTER TABLE chat_sessions ADD COLUMN IF NOT EXISTS archived_at TIMESTAMPTZ NULL")
    op.execute(
        "CREATE INDEX IF NOT EXISTS ix_chat_sessions_owner_active_updated "
        "ON chat_sessions(owner_subject, updated_at DESC) WHERE archived_at IS NULL"
    )


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS ix_chat_sessions_owner_active_updated")
    op.execute("ALTER TABLE chat_sessions DROP COLUMN IF EXISTS archived_at")
    op.execute("ALTER TABLE chat_sessions DROP COLUMN IF EXISTS title")
