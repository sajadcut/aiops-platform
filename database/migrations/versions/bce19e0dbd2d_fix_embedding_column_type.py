"""fix_embedding_column_type

Revision ID: fix_embedding_001
Revises: 0ee48995b0c1
Create Date: 2026-08-22 23:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from pgvector.sqlalchemy import Vector

# revision identifiers, used by Alembic.
revision: str = 'fix_embedding_001'  # ✅ شناسه‌ی یکتا
down_revision: Union[str, None] = '0ee48995b0c1'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # تغییر نوع ستون embedding در هر دو جدول
    op.execute("ALTER TABLE knowledge_documents ALTER COLUMN embedding TYPE vector(1536) USING embedding::vector")
    op.execute("ALTER TABLE memory_entries ALTER COLUMN embedding TYPE vector(1536) USING embedding::vector")


def downgrade() -> None:
    # بازگشت به حالت قبلی (text)
    op.execute("ALTER TABLE knowledge_documents ALTER COLUMN embedding TYPE text USING embedding::text")
    op.execute("ALTER TABLE memory_entries ALTER COLUMN embedding TYPE text USING embedding::text")