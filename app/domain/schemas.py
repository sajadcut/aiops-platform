from pydantic import BaseModel, Field
from datetime import datetime
from typing import Optional, List, Dict, Any
from uuid import UUID

# --- Schemas برای Incident ---
class IncidentCreate(BaseModel):
    source: str
    severity: str
    service: Optional[str] = None
    summary: Optional[str] = None
    context: Optional[Dict[str, Any]] = None

class IncidentResponse(BaseModel):
    id: UUID
    source: str
    severity: str
    service: Optional[str]
    started_at: datetime
    status: str
    summary: Optional[str]
    
    class Config:
        from_attributes = True

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
    id: UUID
    incident_id: UUID
    type: str
    source: str
    reference: Optional[str]
    confidence: float
    
    class Config:
        from_attributes = True

# --- Schemas برای Finding ---
class FindingCreate(BaseModel):
    incident_id: UUID
    agent: str
    finding_type: str
    statement: str
    evidence_ids: Optional[List[UUID]] = None
    confidence: float = 0.0

class FindingResponse(BaseModel):
    id: UUID
    incident_id: UUID
    agent: str
    finding_type: str
    statement: str
    confidence: float
    
    class Config:
        from_attributes = True

# --- State برای LangGraph ---
class AgentState(BaseModel):
    incident_id: Optional[UUID] = None
    messages: List[str] = Field(default_factory=list)
    current_node: str = "start"
    findings: List[FindingResponse] = Field(default_factory=list)
    confidence: float = 0.0
    evidence_ids: List[UUID] = Field(default_factory=list)
    plan: Optional[str] = None