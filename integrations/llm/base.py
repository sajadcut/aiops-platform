from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional
from pydantic import BaseModel

class LLMResponse(BaseModel):
    """نتیجه استاندارد از هر LLM Provider"""
    content: str
    raw_response: Optional[Dict[str, Any]] = None
    model: str
    usage: Optional[Dict[str, int]] = None  # token usage

class LLMAdapter(ABC):
    """اینترفیس انتزاعی برای همه‌ی Providerهای LLM"""
    
    @abstractmethod
    async def generate(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        temperature: float = 0.7,
        max_tokens: int = 1000,
        **kwargs
    ) -> LLMResponse:
        """تولید متن بر اساس prompt"""
        pass
    
    @abstractmethod
    async def generate_with_messages(
        self,
        messages: List[Dict[str, str]],
        temperature: float = 0.7,
        max_tokens: int = 1000,
        **kwargs
    ) -> LLMResponse:
        """تولید متن بر اساس لیست پیام‌ها (قالب OpenAI)"""
        pass
    
    @property
    @abstractmethod
    def provider_name(self) -> str:
        """نام Provider (مثلاً 'mock', 'openai', 'azure')"""
        pass