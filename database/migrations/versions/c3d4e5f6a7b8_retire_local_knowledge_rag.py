"""Retire local PostgreSQL Knowledge RAG while preserving historical content.

Revision ID: c3d4e5f6a7b8
Revises: f2b3c4d5e6f7
"""
from typing import Sequence, Union

from alembic import op

revision: str = "c3d4e5f6a7b8"
down_revision: Union[str, Sequence[str], None] = "f2b3c4d5e6f7"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Preserve any pre-Cognia content for controlled migration/audit, but remove
    # its vector-search capability and active Knowledge table name. Runtime code
    # has no ORM/retriever for this archive.
    op.rename_table("knowledge_documents", "legacy_knowledge_documents_archive")
    op.drop_column("legacy_knowledge_documents_archive", "embedding")
    op.execute(
        "COMMENT ON TABLE legacy_knowledge_documents_archive IS "
        "'Legacy pre-Cognia content archive; not an active RAG source'"
    )


def downgrade() -> None:
    # Downgrade restores only schema compatibility; historical embeddings are not
    # recreated because they are no longer authoritative after Cognia migration.
    op.execute(
        "ALTER TABLE legacy_knowledge_documents_archive "
        "ADD COLUMN embedding vector(1536) NULL"
    )
    op.rename_table("legacy_knowledge_documents_archive", "knowledge_documents")
