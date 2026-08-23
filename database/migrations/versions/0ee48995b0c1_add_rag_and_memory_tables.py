"""Add RAG and Memory tables

Revision ID: 0ee48995b0c1
Revises: 34ec6bd70cb3
Create Date: 2026-08-22 22:54:11.579661

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID


# revision identifiers, used by Alembic.
revision: str = '0ee48995b0c1'
down_revision: Union[str, Sequence[str], None] = '34ec6bd70cb3'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # جدول knowledge_documents
    op.create_table(
        'knowledge_documents',
        sa.Column('id', UUID(as_uuid=True), nullable=False),
        sa.Column('title', sa.String(500), nullable=False),
        sa.Column('content', sa.Text(), nullable=False),
        sa.Column('source', sa.String(255), nullable=False),
        sa.Column('version', sa.String(50), nullable=True),
        sa.Column('extra_metadata', sa.JSON(), nullable=True),
        sa.Column('embedding', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=True),
        sa.Column('updated_at', sa.DateTime(timezone=True), onupdate=sa.text('now()'), nullable=True),
        sa.PrimaryKeyConstraint('id')
    )

    # جدول memory_entries
    op.create_table(
        'memory_entries',
        sa.Column('id', UUID(as_uuid=True), nullable=False),
        sa.Column('incident_id', UUID(as_uuid=True), nullable=True),
        sa.Column('pattern', sa.Text(), nullable=False),
        sa.Column('symptoms', sa.JSON(), nullable=True),
        sa.Column('root_cause', sa.Text(), nullable=True),
        sa.Column('action', sa.Text(), nullable=True),
        sa.Column('verification_result', sa.String(50), nullable=True),
        sa.Column('outcome', sa.Text(), nullable=True),
        sa.Column('environment', sa.String(255), nullable=True),
        sa.Column('service_scope', sa.String(255), nullable=True),
        sa.Column('embedding', sa.Text(), nullable=True),
        sa.Column('reuse_count', sa.Integer(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=True),
        sa.Column('updated_at', sa.DateTime(timezone=True), onupdate=sa.text('now()'), nullable=True),
        sa.PrimaryKeyConstraint('id')
    )


def downgrade() -> None:
    op.drop_table('memory_entries')
    op.drop_table('knowledge_documents')