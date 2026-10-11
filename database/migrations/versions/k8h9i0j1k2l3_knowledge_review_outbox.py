"""Durable human-approved Cognia Knowledge Review and publication outbox.

Revision ID: k8h9i0j1k2l3
Revises: j7g8h9i0j1k2
"""
from typing import Sequence, Union
from alembic import op

revision: str = "k8h9i0j1k2l3"
down_revision: Union[str, Sequence[str], None] = "j7g8h9i0j1k2"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute("""
        CREATE TABLE IF NOT EXISTS knowledge_reviews (
            id UUID PRIMARY KEY,
            source_type VARCHAR(32) NOT NULL,
            incident_id UUID NULL REFERENCES incidents(id),
            memory_id UUID NULL REFERENCES memory_entries(id),
            kb_id INTEGER NOT NULL CHECK(kb_id > 0),
            scope JSONB NOT NULL,
            title VARCHAR(500) NOT NULL,
            content TEXT NOT NULL,
            content_hash VARCHAR(64) NOT NULL,
            revision INTEGER NOT NULL DEFAULT 1 CHECK(revision > 0),
            status VARCHAR(32) NOT NULL DEFAULT 'pending_review',
            created_by VARCHAR(255) NOT NULL,
            reviewed_by VARCHAR(255) NULL,
            review_reason TEXT NULL,
            approved_hash VARCHAR(64) NULL,
            approved_revision INTEGER NULL,
            cognia_knowledge_id INTEGER NULL,
            cognia_revision_id INTEGER NULL,
            published_at TIMESTAMPTZ NULL,
            submitted_at TIMESTAMPTZ NULL,
            publish_attempted_at TIMESTAMPTZ NULL,
            publish_error_code VARCHAR(100) NULL,
            created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
            updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
            CONSTRAINT knowledge_review_status CHECK(
                status IN ('pending_review','approved','rejected',
                           'publishing','publish_failed','submitted','published')
            ),
            CONSTRAINT knowledge_review_source CHECK(source_type IN ('incident','manual'))
        )
    """)
    op.execute("CREATE UNIQUE INDEX IF NOT EXISTS ux_knowledge_reviews_memory_id ON knowledge_reviews(memory_id) WHERE memory_id IS NOT NULL")
    op.execute("CREATE INDEX IF NOT EXISTS ix_knowledge_reviews_status_created ON knowledge_reviews(status,created_at DESC)")
    op.execute("CREATE INDEX IF NOT EXISTS ix_knowledge_reviews_incident ON knowledge_reviews(incident_id)")


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS ix_knowledge_reviews_incident")
    op.execute("DROP INDEX IF EXISTS ix_knowledge_reviews_status_created")
    op.execute("DROP INDEX IF EXISTS ux_knowledge_reviews_memory_id")
    op.execute("DROP TABLE IF EXISTS knowledge_reviews")
