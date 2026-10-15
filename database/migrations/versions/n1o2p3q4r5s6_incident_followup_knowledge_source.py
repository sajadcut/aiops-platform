"""Permit review-only incident follow-up knowledge drafts.

Revision ID: n1o2p3q4r5s6
Revises: m0n1o2p3q4r5

The incident chat already inserts source_type='incident_followup', but
the original outbox constraint only allowed incident/manual and rejected
the write, poisoning the SQLAlchemy session and turning a successful
read-only MCP click into HTTP 500.
"""
from alembic import op

revision = "n1o2p3q4r5s6"
down_revision = "m0n1o2p3q4r5"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
        ALTER TABLE knowledge_reviews
          DROP CONSTRAINT knowledge_review_source
    """)
    op.execute("""
        ALTER TABLE knowledge_reviews
          ADD CONSTRAINT knowledge_review_source
          CHECK (source_type IN ('incident', 'manual', 'incident_followup'))
    """)


def downgrade() -> None:
    # Historical follow-up drafts may already exist. Preserve the records;
    # refuse a downgrade that would silently orphan or delete human reviews.
    op.execute("""
        DO $$
        BEGIN
          IF EXISTS (SELECT 1 FROM knowledge_reviews
                     WHERE source_type = 'incident_followup') THEN
            RAISE EXCEPTION
              'Cannot downgrade while incident_followup knowledge reviews exist';
          END IF;
        END;
        $$;
    """)
    op.execute("ALTER TABLE knowledge_reviews DROP CONSTRAINT knowledge_review_source")
    op.execute("""
        ALTER TABLE knowledge_reviews
          ADD CONSTRAINT knowledge_review_source
          CHECK (source_type IN ('incident', 'manual'))
    """)
