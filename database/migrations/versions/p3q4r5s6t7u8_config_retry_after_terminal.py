"""Allow a newly authorized config request after a terminal nonverified attempt.

Revision ID: p3q4r5s6t7u8
Revises: o2p3q4r5s6t7

Keep exactly one nonterminal approval per incident and exact file digests.
An irrevocably consumed approval can never be reused or made pending again.
A separate, newly bound request is still pending_validation and must pass
fresh live source-CAS, isolated validation, and explicit human approval.
"""
from alembic import op

revision = "p3q4r5s6t7u8"
down_revision = "o2p3q4r5s6t7"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # The former all-status unique index trapped incidents forever after
    # consumed/failed apply. Only active requests need deduplication.
    op.execute("DROP INDEX IF EXISTS ux_config_change_approval_candidate")
    op.execute("""
        CREATE UNIQUE INDEX ux_config_change_approval_candidate
        ON approvals (incident_id, (metadata->>'original_sha256'),
                      (metadata->>'candidate_sha256'))
        WHERE action='apply_configuration_change'
          AND status IN ('pending_validation','pending','approved')
    """)


def downgrade() -> None:
    # Protect audit history: restoring the old index would fail if a new
    # ticket follows a consumed approval. Never delete issued approval rows.
    op.execute("""
        DO $$
        BEGIN
          IF EXISTS (
            SELECT 1 FROM approvals
            WHERE action='apply_configuration_change'
            GROUP BY incident_id, (metadata->>'original_sha256'),
                     (metadata->>'candidate_sha256')
            HAVING COUNT(*) > 1
          ) THEN
            RAISE EXCEPTION
              'Cannot downgrade config approval uniqueness with historical retries';
          END IF;
        END;
        $$;
    """)
    op.execute("DROP INDEX IF EXISTS ux_config_change_approval_candidate")
    op.execute("""
        CREATE UNIQUE INDEX ux_config_change_approval_candidate
        ON approvals (incident_id, (metadata->>'original_sha256'),
                      (metadata->>'candidate_sha256'))
        WHERE action='apply_configuration_change'
    """)
