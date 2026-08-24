from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class ActionPlan(BaseModel):
    action_id: str
    runbook: str
    risk: str
    prerequisites: List[str] = Field(default_factory=list)
    rollback: Optional[str] = None
    expected_effect: Optional[str] = None
    tool_name: Optional[str] = None
    target: Optional[str] = None
    parameters: Dict[str, Any] = Field(default_factory=dict)
    timeout: int = 30
