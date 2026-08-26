from datetime import datetime
from typing import Any, Dict, List, Optional
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


# --- Schemas برای Incident ---
class IncidentCreate(BaseModel):
    source: str
    severity: str
    service: Optional[str] = None
    summary: Optional[str] = None
    context: Optional[Dict[str, Any]] = None


class IncidentResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    source: str
    severity: str
    service: Optional[str]
    started_at: datetime
    status: str
    summary: Optional[str]


# --- Schemas برای Evidence ---
class EvidenceCreate(BaseModel):
    incident_id: UUID
    type: str
    source: str
    query: Optional[str] = None
    time_range: Optional[Dict[str, str]] = None
    reference: Optional[str] = None
    raw_data: Optional[Dict[str, Any]] = None
    confidence: float = 1.0


class EvidenceResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    incident_id: UUID
    type: str
    source: str
    reference: Optional[str]
    confidence: float


# --- Schemas برای Finding ---
class FindingCreate(BaseModel):
    incident_id: UUID
    agent: str
    finding_type: str
    statement: str
    evidence_ids: Optional[List[UUID]] = None
    confidence: float = 0.0


class FindingResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    incident_id: UUID
    agent: str
    finding_type: str
    statement: str
    confidence: float


# --- State برای LangGraph ---
class AgentState(BaseModel):
    incident_id: Optional[UUID] = None
    messages: List[str] = Field(default_factory=list)
    current_node: str = "start"
    findings: List[FindingResponse] = Field(default_factory=list)
    confidence: float = 0.0
    evidence_ids: List[UUID] = Field(default_factory=list)
    plan: Optional[str] = None
