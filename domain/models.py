"""مدل‌های canonical داده برای Incident، Evidence، Finding و Operational Memory.

این فایل تعریف می‌کند چه چیزی در PostgreSQL «واقعیت durable» محسوب می‌شود. تفاوت
Evidence و Finding مهم است: Evidence fact جمع‌آوری‌شده از سیستم واقعی است؛ Finding
تحلیل Agent روی آن factهاست. Governed Knowledge در Cognia است و Operational Memory در PostgreSQL/pgvector باقی می‌ماند.
"""

from sqlalchemy import Column, String, DateTime, JSON, Float, Text, Enum, Integer, Boolean
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.sql import func
from pgvector.sqlalchemy import Vector
from database import Base
import uuid
import enum


class IncidentStatus(str, enum.Enum):
    """Lifecycle سطح Incident؛ workflow node جزئی‌تر در checkpoint نگه داشته می‌شود."""

    OPEN = "open"
    ANALYZING = "analyzing"
    RESOLVED = "resolved"
    CLOSED = "closed"
    ESCALATED = "escalated"


class EvidenceType(str, enum.Enum):
    """نوع fact عملیاتی بدون وابستگی به vendor خاص مثل Zabbix یا Elastic."""

    LOG = "log"
    METRIC = "metric"
    EVENT = "event"
    TRACE = "trace"
    ALERT = "alert"


class Incident(Base):
    """واحد durable کار عملیاتی که چند signal/evidence می‌توانند به آن correlate شوند."""

    __tablename__ = "incidents"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    source = Column(String(255), nullable=False)
    severity = Column(String(50), nullable=False)
    service = Column(String(255), nullable=True)
    started_at = Column(DateTime(timezone=True), server_default=func.now())
    status = Column(Enum(IncidentStatus), default=IncidentStatus.OPEN)
    summary = Column(Text, nullable=True)
    # context برای enrichment و asset/service hints است؛ state اجرایی LangGraph در
    # workflow_checkpoints نگه داشته می‌شود تا این جدول به یک dump از workflow تبدیل نشود.
    context = Column(JSON, nullable=True)

    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())


class Evidence(Base):
    """Evidence خام/normalized با provenance منبع برای یک Incident."""

    __tablename__ = "evidences"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    incident_id = Column(UUID(as_uuid=True), nullable=False)
    type = Column(Enum(EvidenceType), nullable=False)
    source = Column(String(255), nullable=False)
    query = Column(Text, nullable=True)
    time_range = Column(JSON, nullable=True)
    reference = Column(Text, nullable=True)
    raw_data = Column(JSON, nullable=True)
    confidence = Column(Float, default=1.0)

    created_at = Column(DateTime(timezone=True), server_default=func.now())


class Finding(Base):
    """نتیجه تحلیل Agent؛ evidence_ids نشان می‌دهد ادعا بر کدام factها تکیه دارد."""

    __tablename__ = "findings"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    incident_id = Column(UUID(as_uuid=True), nullable=False)
    agent = Column(String(100), nullable=False)
    finding_type = Column(String(100), nullable=False)
    statement = Column(Text, nullable=False)
    evidence_ids = Column(JSON, nullable=True)
    confidence = Column(Float, default=0.0)

    created_at = Column(DateTime(timezone=True), server_default=func.now())


# Governed Knowledge RAG فقط در Cognia نگهداری/بازیابی می‌شود. PostgreSQL هیچ
# Knowledge ORM فعال ندارد؛ pgvector اینجا فقط برای Operational Memory است.
class MemoryEntry(Base):
    """Immutable-style historical incident episode plus mutable reuse statistics."""

    __tablename__ = "memory_entries"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    incident_id = Column(UUID(as_uuid=True), nullable=True)

    # Legacy-compatible projection.
    pattern = Column(Text, nullable=False)
    symptoms = Column(JSON, nullable=True)
    root_cause = Column(Text, nullable=True)
    action = Column(Text, nullable=True)
    verification_result = Column(String(50), nullable=True)
    outcome = Column(Text, nullable=True)
    environment = Column(String(255), nullable=True)
    service_scope = Column(String(255), nullable=True)
    embedding = Column(Vector(1536), nullable=True)
    reuse_count = Column(Integer, default=0)

    # Operational Memory v2 episode.
    memory_schema_version = Column(String(20), nullable=False, default="2.0")
    episode_fingerprint = Column(String(64), nullable=True)
    asset_type = Column(String(100), nullable=True)
    asset_id = Column(String(255), nullable=True)
    hostname = Column(String(255), nullable=True)
    fqdn = Column(String(255), nullable=True)
    platform = Column(String(100), nullable=True)
    namespace = Column(String(255), nullable=True)
    service_version = Column(String(255), nullable=True)
    configuration_fingerprint = Column(String(255), nullable=True)

    trigger = Column(JSON, nullable=True)
    incident_pattern = Column(JSON, nullable=True)
    investigation = Column(JSON, nullable=True)
    evidence_provenance = Column(JSON, nullable=True)

    root_cause_status = Column(String(32), nullable=True, default="unknown")
    root_cause_confidence = Column(Float, default=0.0)
    causal_factors = Column(JSON, nullable=True)
    contributing_factors = Column(JSON, nullable=True)

    actual_remediation = Column(JSON, nullable=True)
    verification = Column(JSON, nullable=True)
    memory_outcome_class = Column(String(64), nullable=True, default="diagnostic_only")
    reusable_lesson = Column(Text, nullable=True)

    lifecycle_status = Column(String(32), nullable=False, default="active")
    valid_from = Column(DateTime(timezone=True), server_default=func.now())
    last_validated_at = Column(DateTime(timezone=True), nullable=True)
    invalidated_at = Column(DateTime(timezone=True), nullable=True)
    invalidation_reason = Column(Text, nullable=True)
    superseded_by_memory_id = Column(UUID(as_uuid=True), nullable=True)

    embedding_document = Column(Text, nullable=True)
    embedding_status = Column(String(32), nullable=False, default="pending")
    embedding_provider = Column(String(100), nullable=True)
    embedding_model = Column(String(255), nullable=True)
    embedding_dimension = Column(Integer, nullable=True)
    embedding_version = Column(String(32), nullable=True, default="1")
    embedding_document_version = Column(String(32), nullable=True, default="1")
    embedding_text_hash = Column(String(64), nullable=True)
    embedded_at = Column(DateTime(timezone=True), nullable=True)
    search_document = Column(Text, nullable=True)

    retrieval_count = Column(Integer, default=0)
    cited_count = Column(Integer, default=0)
    successful_reuse_count = Column(Integer, default=0)
    failed_reuse_count = Column(Integer, default=0)
    effectiveness_score = Column(Float, default=0.0)
    last_retrieved_at = Column(DateTime(timezone=True), nullable=True)
    last_reused_at = Column(DateTime(timezone=True), nullable=True)
    last_successful_reuse_at = Column(DateTime(timezone=True), nullable=True)

    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())


class MemoryReuseEvent(Base):
    """Feedback trail showing how a historical episode affected a later incident."""

    __tablename__ = "memory_reuse_events"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    memory_id = Column(UUID(as_uuid=True), nullable=False)
    target_incident_id = Column(UUID(as_uuid=True), nullable=False)
    retrieved_at = Column(DateTime(timezone=True), server_default=func.now())
    retrieval_mode = Column(String(64), nullable=False)
    vector_similarity = Column(Float, default=0.0)
    lexical_score = Column(Float, default=0.0)
    final_rank_score = Column(Float, default=0.0)
    rank_position = Column(Integer, nullable=True)
    was_presented_to_agent = Column(Boolean, default=False)
    was_cited_by_agent = Column(Boolean, default=False)
    influenced_plan = Column(Boolean, default=False)
    suggested_action = Column(String(255), nullable=True)
    action_executed = Column(Boolean, default=False)
    verification_result = Column(String(50), nullable=True)
    helpful = Column(Boolean, nullable=True)
    reward_score = Column(Float, default=0.0)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
