"""Append-only operator decision snapshots at durable workflow transitions.

Revision ID: l9m0n1o2p3q4
Revises: k8h9i0j1k2l3

Read-only Decision Brief GETs never write. Historical snapshots are written
only by existing audited approval/execution transitions.
"""
from typing import Sequence, Union

from alembic import op

revision: str = "l9m0n1o2p3q4"
down_revision: Union[str, Sequence[str], None] = "k8h9i0j1k2l3"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute("""
        CREATE TABLE incident_decision_brief_snapshots (
            id UUID PRIMARY KEY,
            incident_id UUID NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
            snapshot_hash CHAR(64) NOT NULL,
            event_type VARCHAR(40) NOT NULL,
            checkpoint_version INTEGER NULL,
            approval_id VARCHAR(128) NULL,
            contract_version VARCHAR(64) NOT NULL,
            brief JSONB NOT NULL,
            created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
            CONSTRAINT decision_brief_snapshots_event_ck CHECK (
                event_type IN ('approval_requested','approval_approved',
                               'approval_rejected','execution_finished',
                               'verification_finished','direct_execution_finished')
            ),
            CONSTRAINT decision_brief_snapshots_immutable_snapshot_uniq
                UNIQUE (incident_id, event_type, snapshot_hash)
        )
    """)
    op.execute(
        "CREATE INDEX ix_decision_brief_snapshots_incident_time "
        "ON incident_decision_brief_snapshots (incident_id, created_at DESC)"
    )
    # Block mutation of existing historical documents; only insert and
    # cascading incident retention deletion are allowed.
    op.execute("""
        CREATE FUNCTION block_decision_brief_snapshot_update()
        RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
            RAISE EXCEPTION 'decision_brief_snapshot_immutable';
        END
        $$
    """)
    # Serialize incident Evidence and Workflow Checkpoint writes against the
    # final approval claim on the same incidents row. This closes the interval
    # between approval snapshot recheck and consumed authority.
    op.execute("""
        CREATE FUNCTION lock_incident_on_decision_source_write()
        $$
        DECLARE target_incident UUID;
        BEGIN
            IF TG_OP = 'DELETE' THEN
                target_incident := OLD.incident_id;
            ELSE
                target_incident := NEW.incident_id;
            END IF;
            PERFORM 1 FROM incidents WHERE id=target_incident FOR UPDATE;
            IF TG_OP = 'DELETE' THEN
                RETURN OLD;
            END IF;
            RETURN NEW;
        END
        $$
    """)
    op.execute("""
        CREATE TRIGGER evidence_decision_source_lock
        BEFORE INSERT OR UPDATE OR DELETE ON evidences
        FOR EACH ROW EXECUTE FUNCTION lock_incident_on_decision_source_write()
    """)
    op.execute("""
        CREATE TRIGGER checkpoint_decision_source_lock
        BEFORE INSERT OR UPDATE OR DELETE ON workflow_checkpoints
        FOR EACH ROW EXECUTE FUNCTION lock_incident_on_decision_source_write()
    """)
    op.execute("""
        CREATE TRIGGER decision_brief_snapshots_no_update
        BEFORE UPDATE ON incident_decision_brief_snapshots
        FOR EACH ROW EXECUTE FUNCTION block_decision_brief_snapshot_update()
    """)


def downgrade() -> None:
    op.execute("DROP TRIGGER IF EXISTS checkpoint_decision_source_lock ON workflow_checkpoints")
    op.execute("DROP TRIGGER IF EXISTS evidence_decision_source_lock ON evidences")
    op.execute("DROP FUNCTION IF EXISTS lock_incident_on_decision_source_write()")
    op.execute("DROP TABLE IF EXISTS incident_decision_brief_snapshots")
    op.execute("DROP FUNCTION IF EXISTS block_decision_brief_snapshot_update()")
