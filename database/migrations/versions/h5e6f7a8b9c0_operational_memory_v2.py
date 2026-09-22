"""Operational Memory v2: episodic learning, hybrid retrieval and feedback.

Revision ID: h5e6f7a8b9c0
Revises: g4d5e6f7a8b9
"""
from typing import Sequence, Union

from alembic import op

revision: str = "h5e6f7a8b9c0"
down_revision: Union[str, Sequence[str], None] = "g4d5e6f7a8b9"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    statements = [
        "ALTER TABLE memory_entries ADD COLUMN IF NOT EXISTS memory_schema_version VARCHAR(20) NOT NULL DEFAULT '1.0'",
        "ALTER TABLE memory_entries ADD COLUMN IF NOT EXISTS asset_type VARCHAR(100) NULL",
        "ALTER TABLE memory_entries ADD COLUMN IF NOT EXISTS asset_id VARCHAR(255) NULL",
        "ALTER TABLE memory_entries ADD COLUMN IF NOT EXISTS hostname VARCHAR(255) NULL",
        "ALTER TABLE memory_entries ADD COLUMN IF NOT EXISTS fqdn VARCHAR(255) NULL",
        "ALTER TABLE memory_entries ADD COLUMN IF NOT EXISTS platform VARCHAR(100) NULL",
        "ALTER TABLE memory_entries ADD COLUMN IF NOT EXISTS namespace VARCHAR(255) NULL",
        "ALTER TABLE memory_entries ADD COLUMN IF NOT EXISTS service_version VARCHAR(255) NULL",
        "ALTER TABLE memory_entries ADD COLUMN IF NOT EXISTS configuration_fingerprint VARCHAR(255) NULL",
        "ALTER TABLE memory_entries ADD COLUMN IF NOT EXISTS trigger JSONB NULL",
        "ALTER TABLE memory_entries ADD COLUMN IF NOT EXISTS incident_pattern JSONB NULL",
        "ALTER TABLE memory_entries ADD COLUMN IF NOT EXISTS investigation JSONB NULL",
        "ALTER TABLE memory_entries ADD COLUMN IF NOT EXISTS evidence_provenance JSONB NULL",
        "ALTER TABLE memory_entries ADD COLUMN IF NOT EXISTS root_cause_status VARCHAR(32) NULL DEFAULT 'unknown'",
        "ALTER TABLE memory_entries ADD COLUMN IF NOT EXISTS root_cause_confidence DOUBLE PRECISION NOT NULL DEFAULT 0",
        "ALTER TABLE memory_entries ADD COLUMN IF NOT EXISTS causal_factors JSONB NULL",
        "ALTER TABLE memory_entries ADD COLUMN IF NOT EXISTS contributing_factors JSONB NULL",
        "ALTER TABLE memory_entries ADD COLUMN IF NOT EXISTS actual_remediation JSONB NULL",
        "ALTER TABLE memory_entries ADD COLUMN IF NOT EXISTS verification JSONB NULL",
        "ALTER TABLE memory_entries ADD COLUMN IF NOT EXISTS memory_outcome_class VARCHAR(64) NULL DEFAULT 'diagnostic_only'",
        "ALTER TABLE memory_entries ADD COLUMN IF NOT EXISTS reusable_lesson TEXT NULL",
        "ALTER TABLE memory_entries ADD COLUMN IF NOT EXISTS lifecycle_status VARCHAR(32) NOT NULL DEFAULT 'active'",
        "ALTER TABLE memory_entries ADD COLUMN IF NOT EXISTS valid_from TIMESTAMPTZ NOT NULL DEFAULT now()",
        "ALTER TABLE memory_entries ADD COLUMN IF NOT EXISTS last_validated_at TIMESTAMPTZ NULL",
        "ALTER TABLE memory_entries ADD COLUMN IF NOT EXISTS invalidated_at TIMESTAMPTZ NULL",
        "ALTER TABLE memory_entries ADD COLUMN IF NOT EXISTS invalidation_reason TEXT NULL",
        "ALTER TABLE memory_entries ADD COLUMN IF NOT EXISTS superseded_by_memory_id UUID NULL",
        "ALTER TABLE memory_entries ADD COLUMN IF NOT EXISTS embedding_document TEXT NULL",
        "ALTER TABLE memory_entries ADD COLUMN IF NOT EXISTS embedding_status VARCHAR(32) NOT NULL DEFAULT 'pending'",
        "ALTER TABLE memory_entries ADD COLUMN IF NOT EXISTS embedding_provider VARCHAR(100) NULL",
        "ALTER TABLE memory_entries ADD COLUMN IF NOT EXISTS embedding_model VARCHAR(255) NULL",
        "ALTER TABLE memory_entries ADD COLUMN IF NOT EXISTS embedding_dimension INTEGER NULL",
        "ALTER TABLE memory_entries ADD COLUMN IF NOT EXISTS embedding_version VARCHAR(32) NULL DEFAULT '1'",
        "ALTER TABLE memory_entries ADD COLUMN IF NOT EXISTS embedding_document_version VARCHAR(32) NULL DEFAULT '1'",
        "ALTER TABLE memory_entries ADD COLUMN IF NOT EXISTS embedding_text_hash VARCHAR(64) NULL",
        "ALTER TABLE memory_entries ADD COLUMN IF NOT EXISTS embedded_at TIMESTAMPTZ NULL",
        "ALTER TABLE memory_entries ADD COLUMN IF NOT EXISTS search_document TEXT NULL",
        "ALTER TABLE memory_entries ADD COLUMN IF NOT EXISTS retrieval_count INTEGER NOT NULL DEFAULT 0",
        "ALTER TABLE memory_entries ADD COLUMN IF NOT EXISTS cited_count INTEGER NOT NULL DEFAULT 0",
        "ALTER TABLE memory_entries ADD COLUMN IF NOT EXISTS successful_reuse_count INTEGER NOT NULL DEFAULT 0",
        "ALTER TABLE memory_entries ADD COLUMN IF NOT EXISTS failed_reuse_count INTEGER NOT NULL DEFAULT 0",
        "ALTER TABLE memory_entries ADD COLUMN IF NOT EXISTS effectiveness_score DOUBLE PRECISION NOT NULL DEFAULT 0",
        "ALTER TABLE memory_entries ADD COLUMN IF NOT EXISTS last_retrieved_at TIMESTAMPTZ NULL",
        "ALTER TABLE memory_entries ADD COLUMN IF NOT EXISTS last_reused_at TIMESTAMPTZ NULL",
        "ALTER TABLE memory_entries ADD COLUMN IF NOT EXISTS last_successful_reuse_at TIMESTAMPTZ NULL",
    ]
    for statement in statements:
        op.execute(statement)

    op.execute(
        """
        UPDATE memory_entries
        SET
            embedding_status = CASE WHEN embedding IS NULL THEN 'pending' ELSE 'ready' END,
            embedding_provider = COALESCE(embedding_provider, CASE WHEN embedding IS NULL THEN NULL ELSE 'legacy' END),
            embedding_dimension = COALESCE(embedding_dimension, CASE WHEN embedding IS NULL THEN NULL ELSE 1536 END),
            embedded_at = COALESCE(embedded_at, CASE WHEN embedding IS NULL THEN NULL ELSE COALESCE(updated_at, created_at, now()) END),
            search_document = COALESCE(
                search_document,
                concat_ws(' ', service_scope, pattern, root_cause, action, outcome)
            ),
            memory_outcome_class = COALESCE(
                memory_outcome_class,
                CASE
                    WHEN lower(COALESCE(verification_result,'')) IN ('success','succeeded','verified') THEN 'successful_recovery'
                    WHEN lower(COALESCE(verification_result,'')) = 'partial' THEN 'partial_recovery'
                    WHEN lower(COALESCE(verification_result,'')) IN ('failed','failure') THEN 'failed_recovery'
                    ELSE 'diagnostic_only'
                END
            )
        """
    )

    op.execute(
        """
        CREATE TABLE IF NOT EXISTS memory_reuse_events (
            id UUID PRIMARY KEY,
            memory_id UUID NOT NULL,
            target_incident_id UUID NOT NULL,
            retrieved_at TIMESTAMPTZ NOT NULL DEFAULT now(),
            retrieval_mode VARCHAR(64) NOT NULL,
            vector_similarity DOUBLE PRECISION NOT NULL DEFAULT 0,
            lexical_score DOUBLE PRECISION NOT NULL DEFAULT 0,
            final_rank_score DOUBLE PRECISION NOT NULL DEFAULT 0,
            rank_position INTEGER NULL,
            was_presented_to_agent BOOLEAN NOT NULL DEFAULT false,
            was_cited_by_agent BOOLEAN NOT NULL DEFAULT false,
            influenced_plan BOOLEAN NOT NULL DEFAULT false,
            suggested_action VARCHAR(255) NULL,
            action_executed BOOLEAN NOT NULL DEFAULT false,
            verification_result VARCHAR(50) NULL,
            helpful BOOLEAN NULL,
            reward_score DOUBLE PRECISION NOT NULL DEFAULT 0,
            created_at TIMESTAMPTZ NOT NULL DEFAULT now()
        )
        """
    )

    for statement in [
        "CREATE INDEX IF NOT EXISTS ix_memory_entries_service_scope ON memory_entries(service_scope)",
        "CREATE INDEX IF NOT EXISTS ix_memory_entries_environment ON memory_entries(environment)",
        "CREATE INDEX IF NOT EXISTS ix_memory_entries_verification_result ON memory_entries(verification_result)",
        "CREATE INDEX IF NOT EXISTS ix_memory_entries_outcome_class ON memory_entries(memory_outcome_class)",
        "CREATE INDEX IF NOT EXISTS ix_memory_entries_lifecycle_status ON memory_entries(lifecycle_status)",
        "CREATE INDEX IF NOT EXISTS ix_memory_entries_created_at ON memory_entries(created_at DESC)",
        "CREATE INDEX IF NOT EXISTS ix_memory_entries_embedding_status ON memory_entries(embedding_status)",
        "CREATE INDEX IF NOT EXISTS ix_memory_reuse_events_memory_id ON memory_reuse_events(memory_id)",
        "CREATE INDEX IF NOT EXISTS ix_memory_reuse_events_target_incident_id ON memory_reuse_events(target_incident_id)",
        "CREATE INDEX IF NOT EXISTS ix_memory_reuse_events_created_at ON memory_reuse_events(created_at DESC)",
        "CREATE INDEX IF NOT EXISTS ix_memory_entries_search_document_gin ON memory_entries USING gin (to_tsvector('simple', COALESCE(search_document,'')))",
        "CREATE INDEX IF NOT EXISTS ix_memory_entries_embedding_hnsw_active ON memory_entries USING hnsw (embedding vector_cosine_ops) WHERE embedding IS NOT NULL AND lifecycle_status='active'",
    ]:
        op.execute(statement)


def downgrade() -> None:
    for index_name in [
        "ix_memory_entries_embedding_hnsw_active",
        "ix_memory_entries_search_document_gin",
        "ix_memory_reuse_events_created_at",
        "ix_memory_reuse_events_target_incident_id",
        "ix_memory_reuse_events_memory_id",
        "ix_memory_entries_embedding_status",
        "ix_memory_entries_created_at",
        "ix_memory_entries_lifecycle_status",
        "ix_memory_entries_outcome_class",
        "ix_memory_entries_verification_result",
        "ix_memory_entries_environment",
        "ix_memory_entries_service_scope",
    ]:
        op.execute(f"DROP INDEX IF EXISTS {index_name}")
    op.execute("DROP TABLE IF EXISTS memory_reuse_events")

    columns = [
        "last_successful_reuse_at", "last_reused_at", "last_retrieved_at",
        "effectiveness_score", "failed_reuse_count", "successful_reuse_count",
        "cited_count", "retrieval_count", "search_document", "embedded_at",
        "embedding_text_hash", "embedding_document_version", "embedding_version",
        "embedding_dimension", "embedding_model", "embedding_provider",
        "embedding_status", "embedding_document", "superseded_by_memory_id",
        "invalidation_reason", "invalidated_at", "last_validated_at", "valid_from",
        "lifecycle_status", "reusable_lesson", "memory_outcome_class", "verification",
        "actual_remediation", "contributing_factors", "causal_factors",
        "root_cause_confidence", "root_cause_status", "evidence_provenance",
        "investigation", "incident_pattern", "trigger", "configuration_fingerprint",
        "service_version", "namespace", "platform", "fqdn", "hostname", "asset_id",
        "asset_type", "memory_schema_version",
    ]
    for column in columns:
        op.execute(f"ALTER TABLE memory_entries DROP COLUMN IF EXISTS {column}")
