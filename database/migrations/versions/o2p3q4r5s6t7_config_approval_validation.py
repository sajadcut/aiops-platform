"""Register non-approvable configuration change requests in the Approval queue.

Revision ID: o2p3q4r5s6t7
Revises: n1o2p3q4r5s6

pending_validation is not a valid execution authority. No transition from
this state to pending is offered until an independent validator and guarded
configuration-application contract have been registered.
"""
from alembic import op

revision = "o2p3q4r5s6t7"
down_revision = "n1o2p3q4r5s6"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("ALTER TABLE approvals DROP CONSTRAINT IF EXISTS approvals_status_ck")
    op.execute("""
        ALTER TABLE approvals ADD CONSTRAINT approvals_status_ck
        CHECK (status IN ('pending_validation','pending','approved','rejected','expired','consumed'))
    """)
    # Idempotency is durable across duplicate browser submissions and workers.
    op.execute("""
        CREATE UNIQUE INDEX IF NOT EXISTS ux_config_change_approval_candidate
        ON approvals (incident_id, (metadata->>'original_sha256'),
                      (metadata->>'candidate_sha256'))
        WHERE action = 'apply_configuration_change'
    """)


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS ux_config_change_approval_candidate")
    op.execute("ALTER TABLE approvals DROP CONSTRAINT IF EXISTS approvals_status_ck")
    op.execute("""
        ALTER TABLE approvals ADD CONSTRAINT approvals_status_ck
        CHECK (status IN ('pending','approved','rejected','expired','consumed'))
    """)
