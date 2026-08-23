from sqlalchemy import Column, String, DateTime, JSON, Float, Text, Enum, Integer
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.sql import func
from pgvector.sqlalchemy import Vector
from database import Base
import uuid
import enum

class IncidentStatus(str, enum.Enum):
    OPEN = "open"
    ANALYZING = "analyzing"
    RESOLVED = "resolved"
    CLOSED = "closed"
    ESCALATED = "escalated"

class EvidenceType(str, enum.Enum):
    LOG = "log"
    METRIC = "metric"
    EVENT = "event"
    TRACE = "trace"
    ALERT = "alert"

class Incident(Base):
    __tablename__ = "incidents"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    source = Column(String(255), nullable=False)
    severity = Column(String(50), nullable=False)
    service = Column(String(255), nullable=True)
    started_at = Column(DateTime(timezone=True), server_default=func.now())
    status = Column(Enum(IncidentStatus), default=IncidentStatus.OPEN)
    summary = Column(Text, nullable=True)
    context = Column(JSON, nullable=True)
    
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

class Evidence(Base):
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
    __tablename__ = "findings"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    incident_id = Column(UUID(as_uuid=True), nullable=False)
    agent = Column(String(100), nullable=False)
    finding_type = Column(String(100), nullable=False)
    statement = Column(Text, nullable=False)
    evidence_ids = Column(JSON, nullable=True)
    confidence = Column(Float, default=0.0)
    
    created_at = Column(DateTime(timezone=True), server_default=func.now())

# ============ RAG & Memory ============

class KnowledgeDocument(Base):
    """ذخیره‌سازی دانش (Runbook، مستندات، SOP) با Embedding"""
    __tablename__ = "knowledge_documents"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    title = Column(String(500), nullable=False)
    content = Column(Text, nullable=False)
    source = Column(String(255), nullable=False)
    version = Column(String(50), nullable=True)
    extra_metadata = Column(JSON, nullable=True)  # ✅ تغییر نام از metadata به extra_metadata
    embedding = Column(Vector(1536), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

class MemoryEntry(Base):
    """ذخیره‌سازی تجربه‌ی Incidentها (Operational Memory)"""
    __tablename__ = "memory_entries"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    incident_id = Column(UUID(as_uuid=True), nullable=True)
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
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())