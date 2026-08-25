from __future__ import annotations

from typing import Dict, List, Optional

import httpx

from domain.contracts.config import settings
from integrations.llm.base import LLMAdapter, LLMResponse


class OpenAICompatibleLLMProvider(LLMAdapter):
    """Adapter for an internal/offline OpenAI-compatible chat gateway."""

    def __init__(self, base_url: str, model: str, api_key: Optional[str] = None):
        if not base_url:
            raise ValueError("llm_base_url_required")
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.api_key = api_key

    @property
    def provider_name(self) -> str:
        return "openai-compatible"

    async def generate(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        temperature: float = 0.7,
        max_tokens: int = 1000,
        **kwargs,
    ) -> LLMResponse:
        messages: List[Dict[str, str]] = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})
        return await self.generate_with_messages(messages, temperature, max_tokens, **kwargs)

    async def generate_with_messages(
        self,
        messages: List[Dict[str, str]],
        temperature: float = 0.7,
        max_tokens: int = 1000,
        **kwargs,
    ) -> LLMResponse:
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        async with httpx.AsyncClient(timeout=settings.LLM_TIMEOUT_SECONDS) as client:
            response = await client.post(
                self.base_url + "/chat/completions",
                headers=headers,
                json={
                    "model": self.model,
                    "messages": messages,
                    "temperature": temperature,
                    "max_tokens": max_tokens,
                },
            )
            response.raise_for_status()
            payload = response.json()
        try:
            content = str(payload["choices"][0]["message"]["content"])
        except (KeyError, IndexError, TypeError) as exc:
            raise RuntimeError("invalid_llm_gateway_response") from exc
        return LLMResponse(
            content=content,
            raw_response=payload,
            model=str(payload.get("model") or self.model),
            usage=payload.get("usage"),
        )


def configured_llm_adapter() -> LLMAdapter:
    provider = settings.LLM_PROVIDER.strip().lower()
    if provider == "mock":
        if settings.APP_ENV == "production":
            raise RuntimeError("mock_llm_provider_forbidden_in_production")
        from integrations.llm.mock_provider import MockLLMProvider
        return MockLLMProvider()
    if provider in {"openai-compatible", "openai_compatible"}:
        if not settings.LLM_BASE_URL:
            raise RuntimeError("LLM_BASE_URL is required")
        return OpenAICompatibleLLMProvider(settings.LLM_BASE_URL, settings.LLM_MODEL, settings.LLM_API_KEY)
    raise RuntimeError(f"unsupported_llm_provider:{provider}")
