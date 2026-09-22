"""Add shared API rate-limit counters.

Revision ID: j7g8h9i0j1k2
Revises: i6f7a8b9c0d1
"""

from typing import Sequence, Union

from alembic import op


revision: str = "j7g8h9i0j1k2"
down_revision: Union[str, Sequence[str], None] = "i6f7a8b9c0d1"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute(
        """
        CREATE TABLE IF NOT EXISTS api_rate_limits (
            rate_key VARCHAR(64) PRIMARY KEY,
            window_started_at TIMESTAMPTZ NOT NULL,
            request_count INTEGER NOT NULL CHECK (request_count >= 0),
            updated_at TIMESTAMPTZ NOT NULL
        )
        """
    )
    op.execute(
        """
        CREATE INDEX IF NOT EXISTS ix_api_rate_limits_updated_at
        ON api_rate_limits(updated_at)
        """
    )


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS ix_api_rate_limits_updated_at")
    op.execute("DROP TABLE IF EXISTS api_rate_limits")
