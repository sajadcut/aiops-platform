from abc import ABC, abstractmethod
from typing import Dict, Any, Optional
from pydantic import BaseModel

class ToolInput(BaseModel):
    """ورودی استاندارد برای هر ابزار"""
    action: str
    target: str
    parameters: Dict[str, Any] = {}
    timeout: Optional[int] = 30

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
        """نام ابزار (مثلاً 'ansible', 'kubectl', 'jenkins')"""
        pass
    
    @property
    @abstractmethod
    def risk_level(self) -> str:
        """سطح ریسک: 'low', 'medium', 'high'"""
        return "medium"
    
    @property
    def requires_approval(self) -> bool:
        """آیا اجرای این ابزار نیاز به تایید دارد؟"""
        return self.risk_level != "low"
    
    @abstractmethod
    async def execute(self, input_data: ToolInput) -> ToolOutput:
        """
        اجرای ابزار با ورودی مشخص
        
        Args:
            input_data: پارامترهای اجرا
            
        Returns:
            نتیجه اجرا
        """
        pass
    
    async def validate(self, input_data: ToolInput) -> bool:
        """بررسی اعتبار درخواست قبل از اجرا"""
        return True