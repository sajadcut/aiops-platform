"""Persist operator-maintained, non-executable per-service health profiles.

Revision ID: m0n1o2p3q4r5
Revises: l9m0n1o2p3q4
"""
from alembic import op

revision = "m0n1o2p3q4r5"
down_revision = "l9m0n1o2p3q4"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
        CREATE TABLE service_health_profiles (
            service VARCHAR(120) NOT NULL,
            target VARCHAR(253) NOT NULL,
            profile JSONB NOT NULL,
            updated_by VARCHAR(180) NOT NULL,
            updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            PRIMARY KEY (service, target),
            CONSTRAINT service_health_profile_service_ck
                CHECK (service ~ '^[a-z0-9][a-z0-9_.-]{0,119}$'),
            CONSTRAINT service_health_profile_target_ck
                CHECK (char_length(target) > 0)
        )
    """)


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS service_health_profiles")
