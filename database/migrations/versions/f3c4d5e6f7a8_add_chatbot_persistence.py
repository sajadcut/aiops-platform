"""Add durable AIOps chatbot persistence.

Revision ID: f3c4d5e6f7a8
Revises: c3d4e5f6a7b8
"""
from typing import Sequence, Union

from alembic import op

revision: str = "f3c4d5e6f7a8"
down_revision: Union[str, Sequence[str], None] = "c3d4e5f6a7b8"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute("""
        CREATE TABLE IF NOT EXISTS chat_sessions (
            session_id UUID PRIMARY KEY,
            owner_subject VARCHAR(255) NOT NULL,
            owner_roles JSONB NOT NULL DEFAULT '[]'::jsonb,
            created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
            expires_at TIMESTAMPTZ NOT NULL
        )
    """)
    op.execute("CREATE INDEX IF NOT EXISTS ix_chat_sessions_owner_updated ON chat_sessions(owner_subject, updated_at DESC)")
    op.execute("CREATE INDEX IF NOT EXISTS ix_chat_sessions_expires_at ON chat_sessions(expires_at)")

    op.execute("""
        CREATE TABLE IF NOT EXISTS chat_messages (
            message_id UUID PRIMARY KEY,
            session_id UUID NOT NULL REFERENCES chat_sessions(session_id) ON DELETE CASCADE,
            role VARCHAR(16) NOT NULL,
            content TEXT NOT NULL,
            metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
            created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
            CONSTRAINT chat_messages_role_ck CHECK (role IN ('user','assistant','tool'))
        )
    """)
    op.execute("CREATE INDEX IF NOT EXISTS ix_chat_messages_session_created ON chat_messages(session_id, created_at)")

    op.execute("""
        CREATE TABLE IF NOT EXISTS chat_action_proposals (
            proposal_id UUID PRIMARY KEY,
            session_id UUID NOT NULL REFERENCES chat_sessions(session_id) ON DELETE CASCADE,
            incident_id UUID NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
            owner_subject VARCHAR(255) NOT NULL,
            tool_name VARCHAR(120) NOT NULL,
            action VARCHAR(120) NOT NULL,
            target VARCHAR(255) NOT NULL,
            parameters JSONB NOT NULL DEFAULT '{}'::jsonb,
            risk_level VARCHAR(50) NOT NULL,
            status VARCHAR(30) NOT NULL DEFAULT 'pending',
            binding_digest CHAR(64) NOT NULL,
            approval_id UUID NULL REFERENCES approvals(approval_id) ON DELETE SET NULL,
            execution_result JSONB NULL,
            expires_at TIMESTAMPTZ NOT NULL,
            created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
            CONSTRAINT chat_action_status_ck CHECK (status IN ('pending','confirmed','rejected','executed','failed','expired'))
        )
    """)
    op.execute("CREATE INDEX IF NOT EXISTS ix_chat_action_session_created ON chat_action_proposals(session_id, created_at DESC)")
    op.execute("CREATE INDEX IF NOT EXISTS ix_chat_action_owner_status ON chat_action_proposals(owner_subject, status)")
    op.execute("CREATE INDEX IF NOT EXISTS ix_chat_action_expires_at ON chat_action_proposals(expires_at)")


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS chat_action_proposals")
    op.execute("DROP TABLE IF EXISTS chat_messages")
    op.execute("DROP TABLE IF EXISTS chat_sessions")
