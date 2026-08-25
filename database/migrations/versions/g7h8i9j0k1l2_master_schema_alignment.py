"""Align operational persistence tables with MASTER.md.

Revision ID: g7h8i9j0k1l2
Revises: f1a2b3c4d5e6
"""
from typing import Sequence, Union

from alembic import op

revision: str = "g7h8i9j0k1l2"
down_revision: Union[str, Sequence[str], None] = "f1a2b3c4d5e6"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute("""
        DO $$
        BEGIN
            IF EXISTS (
                SELECT 1 FROM information_schema.columns
                WHERE table_name='incidents' AND column_name='incident_id'
            ) AND NOT EXISTS (
                SELECT 1 FROM information_schema.columns
                WHERE table_name='incidents' AND column_name='id'
            ) THEN
                ALTER TABLE incidents RENAME COLUMN incident_id TO id;
            END IF;
        END $$;
    """)
    op.execute("ALTER TABLE incidents ALTER COLUMN service DROP NOT NULL")
    op.execute("ALTER TABLE incidents ADD COLUMN IF NOT EXISTS context JSONB")
    op.execute("CREATE INDEX IF NOT EXISTS ix_incidents_service ON incidents(service)")
    op.execute("CREATE INDEX IF NOT EXISTS ix_incidents_status ON incidents(status)")

    op.execute("""
        CREATE TABLE IF NOT EXISTS evidences (
            id UUID PRIMARY KEY,
            incident_id UUID NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
            type VARCHAR(32) NOT NULL,
            source VARCHAR(255) NOT NULL,
            query TEXT NULL,
            time_range JSONB NULL,
            reference TEXT NULL,
            raw_data JSONB NULL,
            confidence DOUBLE PRECISION NOT NULL DEFAULT 1.0,
            created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
    """)
    op.execute("CREATE INDEX IF NOT EXISTS ix_evidences_incident_id ON evidences(incident_id)")
    op.execute("CREATE INDEX IF NOT EXISTS ix_evidences_source ON evidences(source)")

    op.execute("""
        CREATE TABLE IF NOT EXISTS findings (
            id UUID PRIMARY KEY,
            incident_id UUID NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
            agent VARCHAR(100) NOT NULL,
            finding_type VARCHAR(100) NOT NULL,
            statement TEXT NOT NULL,
            evidence_ids JSONB NULL,
            confidence DOUBLE PRECISION NOT NULL DEFAULT 0.0,
            created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
    """)
    op.execute("CREATE INDEX IF NOT EXISTS ix_findings_incident_id ON findings(incident_id)")
    op.execute("CREATE INDEX IF NOT EXISTS ix_findings_agent ON findings(agent)")

    op.execute("""
        INSERT INTO evidences (id, incident_id, type, source, query, time_range, reference, raw_data, confidence, created_at)
        SELECT gen_random_uuid(), ie.incident_id,
               COALESCE(ie.evidence_type, 'event'),
               COALESCE(ie.source, 'unknown'), NULL, NULL,
               ie.reference, ie.payload, 1.0, COALESCE(ie.created_at, CURRENT_TIMESTAMP)
        FROM incident_evidence ie
        WHERE EXISTS (SELECT 1 FROM incidents i WHERE i.id = ie.incident_id)
          AND NOT EXISTS (
              SELECT 1 FROM evidences e
              WHERE e.incident_id = ie.incident_id
                AND COALESCE(e.reference, '') = COALESCE(ie.reference, '')
          )
    """)

    op.execute("""
        INSERT INTO findings (id, incident_id, agent, finding_type, statement, evidence_ids, confidence, created_at)
        SELECT gen_random_uuid(), inf.incident_id,
               COALESCE(inf.agent, 'unknown'),
               COALESCE(inf.finding_type, 'finding'),
               COALESCE(inf.statement, 'Legacy finding'),
               inf.evidence_ids,
               COALESCE(inf.confidence, 0.0),
               COALESCE(inf.created_at, CURRENT_TIMESTAMP)
        FROM incident_findings inf
        WHERE EXISTS (SELECT 1 FROM incidents i WHERE i.id = inf.incident_id)
          AND NOT EXISTS (
              SELECT 1 FROM findings f
              WHERE f.incident_id = inf.incident_id
                AND f.statement = COALESCE(inf.statement, 'Legacy finding')
          )
    """)

    op.execute("ALTER TABLE memory_entries ADD COLUMN IF NOT EXISTS extra_metadata JSONB")
    op.execute("CREATE INDEX IF NOT EXISTS ix_memory_entries_incident_id ON memory_entries(incident_id)")
    op.execute("CREATE INDEX IF NOT EXISTS ix_memory_entries_service_scope ON memory_entries(service_scope)")

    op.execute("""
        CREATE TABLE IF NOT EXISTS action_plans (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            incident_id UUID NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
            plan TEXT NOT NULL,
            confidence DOUBLE PRECISION NOT NULL DEFAULT 0.0,
            evidence_ids JSONB NOT NULL DEFAULT '[]'::jsonb,
            status VARCHAR(32) NOT NULL DEFAULT 'proposed',
            created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
    """)
    op.execute("CREATE INDEX IF NOT EXISTS ix_action_plans_incident_id ON action_plans(incident_id)")

    op.execute("""
        CREATE TABLE IF NOT EXISTS policy_decisions (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            incident_id UUID NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
            action VARCHAR(64) NOT NULL,
            risk_level VARCHAR(32) NOT NULL,
            reason TEXT NOT NULL,
            requires_approval BOOLEAN NOT NULL DEFAULT TRUE,
            metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
            created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
    """)
    op.execute("CREATE INDEX IF NOT EXISTS ix_policy_decisions_incident_id ON policy_decisions(incident_id)")

    op.execute("""
        CREATE TABLE IF NOT EXISTS execution_results (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            incident_id UUID NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
            approval_id UUID NULL,
            tool_name VARCHAR(128) NOT NULL,
            action VARCHAR(255) NOT NULL,
            target VARCHAR(255) NOT NULL,
            success BOOLEAN NOT NULL,
            execution_blocked BOOLEAN NOT NULL DEFAULT FALSE,
            reason VARCHAR(255) NULL,
            result JSONB NULL,
            error TEXT NULL,
            execution_time DOUBLE PRECISION NULL,
            created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
    """)
    op.execute("CREATE INDEX IF NOT EXISTS ix_execution_results_incident_id ON execution_results(incident_id)")

    op.execute("""
        CREATE TABLE IF NOT EXISTS verification_results (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            incident_id UUID NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
            execution_id UUID NULL,
            status VARCHAR(32) NOT NULL,
            before_state JSONB NOT NULL DEFAULT '{}'::jsonb,
            after_state JSONB NOT NULL DEFAULT '{}'::jsonb,
            changes JSONB NOT NULL DEFAULT '[]'::jsonb,
            confidence DOUBLE PRECISION NOT NULL DEFAULT 0.0,
            evidence_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
            message TEXT NULL,
            created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
    """)
    op.execute("CREATE INDEX IF NOT EXISTS ix_verification_results_incident_id ON verification_results(incident_id)")


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS verification_results")
    op.execute("DROP TABLE IF EXISTS execution_results")
    op.execute("DROP TABLE IF EXISTS policy_decisions")
    op.execute("DROP TABLE IF EXISTS action_plans")
    op.execute("DROP TABLE IF EXISTS findings")
    op.execute("DROP TABLE IF EXISTS evidences")