import random
import json
from typing import List, Dict, Optional
from integrations.llm.base import LLMAdapter, LLMResponse
from domain.contracts.retry import with_retry
from domain.contracts.logging import logger

class MockLLMProvider(LLMAdapter):
    @property
    def provider_name(self) -> str:
        return "mock"
    
    @with_retry(max_retries=3, delay_seconds=0.5)
    async def generate(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        temperature: float = 0.7,
        max_tokens: int = 1000,
        **kwargs
    ) -> LLMResponse:
        logger.info(f"MockLLM generating response...")
        
        # تشخیص نوع از prompt
        if "triage" in prompt.lower():
            if "http 500" in prompt or "error rate" in prompt:
                response_content = json.dumps({
                    "incident_type": "application",
                    "severity": "High",
                    "description": "Application error spike detected, likely deployment-related",
                    "confidence": 0.75,
                    "recommendations": ["Check deployment logs", "Rollback if needed"]
                })
            elif "cpu" in prompt or "memory" in prompt:
                response_content = json.dumps({
                    "incident_type": "infrastructure",
                    "severity": "High",
                    "description": "Resource saturation detected",
                    "confidence": 0.65,
                    "recommendations": ["Scale resources", "Check node health"]
                })
            else:
                response_content = json.dumps({
                    "incident_type": "application",
                    "severity": "Medium",
                    "description": "General incident, needs further analysis",
                    "confidence": 0.5,
                    "recommendations": ["Investigate logs"]
                })
        else:
            response_content = json.dumps({
                "error_pattern": "HTTP errors detected",
                "deployment_related": True,
                "dependency_issues": ["Database", "Cache"],
                "confidence": 0.7,
                "immediate_actions": ["Restart service", "Check config"]
            })
        
        return LLMResponse(
            content=response_content,
            model="mock-model",
            usage={"prompt_tokens": 100, "completion_tokens": 50}
        )
    
    @with_retry(max_retries=2, delay_seconds=0.3)
    async def generate_with_messages(
        self,
        messages: List[Dict[str, str]],
        temperature: float = 0.7,
        max_tokens: int = 1000,
        **kwargs
    ) -> LLMResponse:
        last_user_msg = next((m["content"] for m in reversed(messages) if m["role"] == "user"), "")
        return await self.generate(last_user_msg, temperature=temperature, max_tokens=max_tokens)