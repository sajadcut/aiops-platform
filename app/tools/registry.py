from typing import Dict, List, Optional, Type
from app.tools.base import BaseTool, ToolInput
from app.core.logging import logger
import asyncio

class ToolRegistry:
    """ثبت‌نامه مرکزی برای مدیریت ابزارهای مجاز"""
    
    _instance: Optional['ToolRegistry'] = None
    _tools: Dict[str, BaseTool] = {}
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._tools = {}
        return cls._instance
    
    def register(self, tool: BaseTool) -> None:
        """ثبت یک ابزار جدید در رجیستری"""
        if tool.name in self._tools:
            logger.warning(f"Tool '{tool.name}' already registered, overwriting")
        self._tools[tool.name] = tool
        logger.info(f"Tool '{tool.name}' registered (risk: {tool.risk_level})")
    
    def get_tool(self, name: str) -> Optional[BaseTool]:
        """دریافت ابزار با نام مشخص"""
        return self._tools.get(name)
    
    def list_tools(self, risk_level: Optional[str] = None) -> List[str]:
        """لیست تمام ابزارها یا فیلتر شده بر اساس ریسک"""
        tools = self._tools.values()
        if risk_level:
            tools = [t for t in tools if t.risk_level == risk_level]
        return [t.name for t in tools]
    
    def get_allowed_tools(self, agent_name: str, risk_level: Optional[str] = None) -> List[str]:
        """
        دریافت لیست ابزارهای مجاز برای یک Agent خاص
        (در آینده می‌توان سیاست‌های دقیق‌تری اعمال کرد)
        """
        all_tools = self.list_tools(risk_level)
        # فعلاً همه ابزارها را برمی‌گرداند، بعداً می‌توان policy اعمال کرد
        return all_tools
    
    async def execute_tool(
        self, 
        tool_name: str, 
        input_data: ToolInput,
        agent_name: str
    ) -> Dict[str, any]:
        """
        اجرای یک ابزار با بررسی مجوزها و محدودیت‌ها
        """
        tool = self.get_tool(tool_name)
        if not tool:
            error_msg = f"Tool '{tool_name}' not found in registry"
            logger.error(error_msg)
            return {"success": False, "error": error_msg}
        
        # بررسی اینکه آیا Agent مجاز به استفاده از این ابزار است
        # (در این مرحله ساده، در آینده با policy کامل‌تر)
        logger.info(f"Agent '{agent_name}' executing tool '{tool_name}'")
        
        # اجرای ابزار
        try:
            result = await tool.execute(input_data)
            return result.model_dump()
        except Exception as e:
            logger.error(f"Tool execution failed: {str(e)}")
            return {"success": False, "error": str(e)}

# ایجاد یک نمونه Singleton
tool_registry = ToolRegistry()