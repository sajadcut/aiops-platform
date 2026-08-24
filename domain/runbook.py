from typing import List, Optional
from pydantic import BaseModel, Field


class Runbook(BaseModel):
    name: str
    owner: str
    version: str
    risk_level: str
    preconditions: List[str] = Field(default_factory=list)
    steps: List[str] = Field(default_factory=list)
    timeout: int = 300
    rollback: Optional[str] = None
    enabled: bool = True
