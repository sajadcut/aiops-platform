"""Add governance and durable workflow persistence.

Revision ID: f1a2b3c4d5e6
Revises: fix_embedding_001
"""
from typing import Sequence, Union

from alembic import op

revision: str = "f1a2b3c4d5e6"
down_revision: Union[str, Sequence[str], None] = "fix_embedding_001"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute("""
        CREATE TABLE IF NOT EXISTS approvals (
            approval_id UUID PRIMARY KEY,
            incident_id UUID NULL REFERENCES incidents(id) ON DELETE CASCADE,
            action TEXT NOT NULL,
            risk_level VARCHAR(50) NOT NULL,
            approver VARCHAR(255) NOT NULL,
            status VARCHAR(30) NOT NULL DEFAULT 'pending',
            metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
            created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
            approved_at TIMESTAMPTZ NULL,
            rejected_at TIMESTAMPTZ NULL,
            CONSTRAINT approvals_status_ck CHECK (status IN ('pending','approved','rejected','expired','consumed'))
        )
    """)
    op.execute("CREATE INDEX IF NOT EXISTS ix_approvals_incident_id ON approvals(incident_id)")
    op.execute("CREATE INDEX IF NOT EXISTS ix_approvals_status ON approvals(status)")

    op.execute("""
        CREATE TABLE IF NOT EXISTS audit_events (
            event_id UUID PRIMARY KEY,
            event_type VARCHAR(120) NOT NULL,
            actor VARCHAR(255) NOT NULL,
            incident_id UUID NULL REFERENCES incidents(id) ON DELETE SET NULL,
            action TEXT NULL,
            status VARCHAR(50) NOT NULL,
            metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
            created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
    """)
    op.execute("CREATE INDEX IF NOT EXISTS ix_audit_events_incident_id ON audit_events(incident_id)")
    op.execute("CREATE INDEX IF NOT EXISTS ix_audit_events_created_at ON audit_events(created_at)")

    op.execute("""
        CREATE TABLE IF NOT EXISTS runbooks (
            runbook_id UUID PRIMARY KEY,
            name VARCHAR(255) NOT NULL UNIQUE,
            version VARCHAR(50) NOT NULL,
            owner VARCHAR(255) NOT NULL,
            risk_level VARCHAR(50) NOT NULL,
            preconditions JSONB NOT NULL DEFAULT '[]'::jsonb,
            steps JSONB NOT NULL DEFAULT '[]'::jsonb,
            timeout_seconds INTEGER NOT NULL DEFAULT 300,
            rollback_steps JSONB NOT NULL DEFAULT '[]'::jsonb,
            enabled BOOLEAN NOT NULL DEFAULT TRUE,
            created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
    """)

    op.execute("""
        CREATE TABLE IF NOT EXISTS workflow_checkpoints (
            incident_id UUID PRIMARY KEY REFERENCES incidents(id) ON DELETE CASCADE,
            state JSONB NOT NULL,
            status VARCHAR(32) NOT NULL DEFAULT 'paused',
            version BIGINT NOT NULL DEFAULT 1,
            updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
    """)
    op.execute("CREATE INDEX IF NOT EXISTS idx_workflow_checkpoints_status ON workflow_checkpoints(status)")


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS workflow_checkpoints")
    op.execute("DROP TABLE IF EXISTS runbooks")
    op.execute("DROP TABLE IF EXISTS audit_events")
    op.execute("DROP TABLE IF EXISTS approvals")
