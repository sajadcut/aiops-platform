"""Allow one-time consumed approval state for anti-replay.

Revision ID: f2b3c4d5e6f7
Revises: f1a2b3c4d5e6
"""
from typing import Sequence, Union

from alembic import op

revision: str = "f2b3c4d5e6f7"
down_revision: Union[str, Sequence[str], None] = "f1a2b3c4d5e6"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute("ALTER TABLE approvals DROP CONSTRAINT IF EXISTS approvals_status_ck")
    op.execute(
        "ALTER TABLE approvals ADD CONSTRAINT approvals_status_ck "
        "CHECK (status IN ('pending','approved','rejected','expired','consumed'))"
    )


def downgrade() -> None:
    op.execute("UPDATE approvals SET status='expired' WHERE status='consumed'")
    op.execute("ALTER TABLE approvals DROP CONSTRAINT IF EXISTS approvals_status_ck")
    op.execute(
        "ALTER TABLE approvals ADD CONSTRAINT approvals_status_ck "
        "CHECK (status IN ('pending','approved','rejected','expired'))"
    )
