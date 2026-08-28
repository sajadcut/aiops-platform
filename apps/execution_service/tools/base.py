from abc import ABC, abstractmethod
from typing import Dict, Any, Optional
from pydantic import BaseModel, Field


class ToolInput(BaseModel):
    """Standard, policy-bound input for an execution tool."""
    action: str
    target: str
    parameters: Dict[str, Any] = Field(default_factory=dict)
    timeout: Optional[int] = 30
    incident_id: Optional[str] = None
    approval_id: Optional[str] = None
    execution_capability: Optional[str] = None
    runbook_id: Optional[str] = None
    runbook_version: Optional[str] = None
    rollback: bool = False


class ToolOutput(BaseModel):
    success: bool
    result: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    execution_time: Optional[float] = None


class BaseTool(ABC):
    @property
    @abstractmethod
    def name(self) -> str:
        pass

    @property
    @abstractmethod
    def risk_level(self) -> str:
        return "medium"

    @property
    def requires_approval(self) -> bool:
        return self.risk_level != "low"

    @abstractmethod
    async def execute(self, input_data: ToolInput) -> ToolOutput:
        pass

    async def validate(self, input_data: ToolInput) -> bool:
        return True
