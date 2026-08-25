"""Initial canonical Incident, Evidence and Finding schema.

Revision ID: 34ec6bd70cb3
Revises: None
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID

revision: str = "34ec6bd70cb3"
down_revision: Union[str, Sequence[str], None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

incident_status = sa.Enum("OPEN", "ANALYZING", "RESOLVED", "CLOSED", "ESCALATED", name="incidentstatus")
evidence_type = sa.Enum("LOG", "METRIC", "EVENT", "TRACE", "ALERT", name="evidencetype")


def upgrade() -> None:
    op.create_table(
        "incidents",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("source", sa.String(255), nullable=False),
        sa.Column("severity", sa.String(50), nullable=False),
        sa.Column("service", sa.String(255), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), server_default=sa.text("now()")),
        sa.Column("status", incident_status, nullable=False, server_default="OPEN"),
        sa.Column("summary", sa.Text(), nullable=True),
        sa.Column("context", sa.JSON(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_incidents_status", "incidents", ["status"])
    op.create_index("ix_incidents_service", "incidents", ["service"])

    op.create_table(
        "evidences",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("incident_id", UUID(as_uuid=True), nullable=False),
        sa.Column("type", evidence_type, nullable=False),
        sa.Column("source", sa.String(255), nullable=False),
        sa.Column("query", sa.Text(), nullable=True),
        sa.Column("time_range", sa.JSON(), nullable=True),
        sa.Column("reference", sa.Text(), nullable=True),
        sa.Column("raw_data", sa.JSON(), nullable=True),
        sa.Column("confidence", sa.Float(), nullable=False, server_default="1"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()")),
        sa.ForeignKeyConstraint(["incident_id"], ["incidents.id"], ondelete="CASCADE"),
    )
    op.create_index("ix_evidences_incident_id", "evidences", ["incident_id"])

    op.create_table(
        "findings",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("incident_id", UUID(as_uuid=True), nullable=False),
        sa.Column("agent", sa.String(100), nullable=False),
        sa.Column("finding_type", sa.String(100), nullable=False),
        sa.Column("statement", sa.Text(), nullable=False),
        sa.Column("evidence_ids", sa.JSON(), nullable=True),
        sa.Column("confidence", sa.Float(), nullable=False, server_default="0"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()")),
        sa.ForeignKeyConstraint(["incident_id"], ["incidents.id"], ondelete="CASCADE"),
    )
    op.create_index("ix_findings_incident_id", "findings", ["incident_id"])


def downgrade() -> None:
    op.drop_table("findings")
    op.drop_table("evidences")
    op.drop_table("incidents")
    bind = op.get_bind()
    evidence_type.drop(bind, checkfirst=True)
    incident_status.drop(bind, checkfirst=True)
