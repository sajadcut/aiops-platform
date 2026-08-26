from abc import ABC, abstractmethod
from typing import Dict, Any, Optional
from pydantic import BaseModel, Field


class ToolInput(BaseModel):
    """ورودی استاندارد برای هر ابزار"""
    action: str
    target: str
    parameters: Dict[str, Any] = Field(default_factory=dict)
    timeout: Optional[int] = 30
    approval_id: Optional[str] = None


class ToolOutput(BaseModel):
    """خروجی استاندارد از هر ابزار"""
    success: bool
    result: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    execution_time: Optional[float] = None


class BaseTool(ABC):
    """کلاس پایه برای همه ابزارهای اجرایی"""

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
