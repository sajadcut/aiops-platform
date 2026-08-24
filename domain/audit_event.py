from typing import Any, Dict, Optional
from datetime import datetime
from pydantic import BaseModel, Field


class AuditEvent(BaseModel):
    event_type: str
    actor: str
    incident_id: Optional[str] = None
    action: Optional[str] = None
    status: str = "recorded"
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    metadata: Dict[str, Any] = Field(default_factory=dict)
