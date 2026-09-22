"""Add Operational Memory episode idempotency fingerprint.

Revision ID: i6f7a8b9c0d1
Revises: h5e6f7a8b9c0
"""

from typing import Sequence, Union

from alembic import op


revision: str = "i6f7a8b9c0d1"
down_revision: Union[str, Sequence[str], None] = "h5e6f7a8b9c0"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute(
        "ALTER TABLE memory_entries "
        "ADD COLUMN IF NOT EXISTS episode_fingerprint VARCHAR(64) NULL"
    )
    op.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS "
        "ux_memory_entries_episode_fingerprint "
        "ON memory_entries(episode_fingerprint) "
        "WHERE episode_fingerprint IS NOT NULL"
    )


def downgrade() -> None:
    op.execute(
        "DROP INDEX IF EXISTS ux_memory_entries_episode_fingerprint"
    )
    op.execute(
        "ALTER TABLE memory_entries "
        "DROP COLUMN IF EXISTS episode_fingerprint"
    )
