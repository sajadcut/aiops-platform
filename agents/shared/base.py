from abc import ABC, abstractmethod
from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field
from datetime import datetime

class AgentInput(BaseModel):
    """ورودی استاندارد به هر Agent"""
    incident_id: Optional[str] = None
    evidence_summary: str = Field(..., description="خلاصه شواهد موجود")
    service_name: Optional[str] = None
    time_range: Optional[Dict[str, str]] = None
    context: Dict[str, Any] = Field(default_factory=dict)

class AgentOutput(BaseModel):
    """خروجی استاندارد از هر Agent"""
    agent_name: str
    finding_type: str
    statement: str
    confidence: float = Field(ge=0, le=1)
    evidence_ids: List[str] = Field(default_factory=list)
    recommendations: List[str] = Field(default_factory=list)
    requires_approval: bool = False
    timestamp: datetime = Field(default_factory=datetime.now)

class BaseAgent(ABC):
    """کلاس پایه انتزاعی برای همه Agentها"""
    
    @property
    @abstractmethod
    def name(self) -> str:
        """نام Agent (مثلاً 'triage', 'application', 'infrastructure')"""
        pass
    
    @property
    @abstractmethod
    def description(self) -> str:
        """توضیح مختصر درباره وظیفه Agent"""
        pass
    
    @property
    def allowed_tools(self) -> List[str]:
        """لیست نام ابزارهایی که این Agent مجاز به استفاده دارد"""
        return []  # پیش‌فرض: هیچ ابزاری مجاز نیست
    
    @abstractmethod
    async def analyze(self, input_data: AgentInput) -> AgentOutput:
        """
        متد اصلی تحلیل که توسط هر Agent پیاده‌سازی می‌شود.
        
        Args:
            input_data: اطلاعات ورودی شامل شواهد و context
            
        Returns:
            خروجی استاندارد شامل یافته‌ها و توصیه‌ها
        """
        pass
    
    async def validate_input(self, input_data: AgentInput) -> bool:
        """بررسی اعتبار ورودی (قابل override توسط Agentهای خاص)"""
        return True