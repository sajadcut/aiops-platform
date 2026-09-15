from __future__ import annotations

from typing import Any, Dict, List, Optional
from uuid import uuid4

from integrations.http_transport import insecure_async_client

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

    @property
    def chat_endpoint(self) -> str:
        return self.base_url + "/chat/completions"

    def _request_headers(self, **kwargs: Any) -> Dict[str, str]:
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        return headers

    def _request_payload(
        self,
        messages: List[Dict[str, str]],
        temperature: float,
        max_tokens: int,
        **kwargs: Any,
    ) -> Dict[str, Any]:
        return {
            "model": self.model,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
        }

    @staticmethod
    def _response_from_payload(payload: Dict[str, Any], fallback_model: str) -> LLMResponse:
        try:
            choice = payload["choices"][0]
            message = choice["message"]
        except (KeyError, IndexError, TypeError) as exc:
            raise RuntimeError("invalid_llm_gateway_response") from exc
        if not isinstance(message, dict):
            raise RuntimeError("invalid_llm_gateway_response")

        raw_content = message.get("content")
        content = "" if raw_content is None else str(raw_content)
        raw_tool_calls = message.get("tool_calls")
        tool_calls = raw_tool_calls if isinstance(raw_tool_calls, list) else None
        finish_reason = choice.get("finish_reason") if isinstance(choice, dict) else None

        return LLMResponse(
            content=content,
            raw_response=payload,
            model=str(payload.get("model") or fallback_model),
            usage=payload.get("usage"),
            tool_calls=tool_calls,
            finish_reason=str(finish_reason) if finish_reason is not None else None,
        )

    async def generate(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        temperature: float = 0.7,
        max_tokens: int = 1000,
        **kwargs: Any,
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
        **kwargs: Any,
    ) -> LLMResponse:
        headers = self._request_headers(**kwargs)
        request_payload = self._request_payload(messages, temperature, max_tokens, **kwargs)
        async with insecure_async_client(timeout=settings.LLM_TIMEOUT_SECONDS) as client:
            response = await client.post(
                self.chat_endpoint,
                headers=headers,
                json=request_payload,
            )
            response.raise_for_status()
            payload = response.json()
        if not isinstance(payload, dict):
            raise RuntimeError("invalid_llm_gateway_response")
        return self._response_from_payload(payload, self.model)


class DotinGeneralChatbotLLMProvider(OpenAICompatibleLLMProvider):
    """Dotin General Chatbot adapter based on the documented OpenAI-compatible API.

    The project uses the non-streaming request/response path. Function/tool-call
    responses are returned as structured metadata only; this adapter never
    executes tools and therefore does not bypass AIOps MCP/approval boundaries.
    """

    ALLOWED_MODELS = {"assistance-model", "developer-model"}
    ALLOWED_REASONING_EFFORT = {"low", "medium", "high", "xhigh", "max", "xmax"}

    def __init__(self, base_url: str, model: str, api_key: Optional[str] = None):
        super().__init__(base_url, model, api_key)
        if self.model not in self.ALLOWED_MODELS:
            raise ValueError("dotin_llm_model_must_be_assistance_or_developer_model")
        if not str(self.api_key or "").strip():
            raise ValueError("dotin_llm_bearer_token_required")

    @property
    def provider_name(self) -> str:
        return "dotin-general-chatbot"

    @property
    def chat_endpoint(self) -> str:
        base = self.base_url.rstrip("/")
        if base.endswith("/v1/chat/completions"):
            return base
        if base.endswith("/chat/completions"):
            return base
        if base.endswith("/v1"):
            return base + "/chat/completions"
        return base + "/v1/chat/completions"

    @staticmethod
    def _safe_header_value(value: Any, *, fallback: str) -> str:
        text = str(value or "").strip() or fallback
        if "\r" in text or "\n" in text:
            raise ValueError("invalid_llm_header_value")
        return text

    def _request_headers(self, **kwargs: Any) -> Dict[str, str]:
        request_id = self._safe_header_value(kwargs.get("request_id"), fallback=str(uuid4()))
        session_id = self._safe_header_value(kwargs.get("session_id"), fallback=request_id)
        user_id = self._safe_header_value(kwargs.get("user_id"), fallback="aiops-platform")
        return {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
            "x-request-id": request_id,
            "x-session-id": session_id,
            "x-user-id": user_id,
        }

    def _request_payload(
        self,
        messages: List[Dict[str, str]],
        temperature: float,
        max_tokens: int,
        **kwargs: Any,
    ) -> Dict[str, Any]:
        stream = bool(kwargs.get("stream", False))
        if stream:
            raise ValueError("dotin_streaming_not_supported_by_aiops_adapter")

        reasoning_effort = str(kwargs.get("reasoning_effort", "medium")).strip().lower()
        if reasoning_effort not in self.ALLOWED_REASONING_EFFORT:
            raise ValueError("invalid_dotin_reasoning_effort")

        enable_thinking = kwargs.get("enable_thinking", False)
        if not isinstance(enable_thinking, bool):
            raise ValueError("dotin_enable_thinking_must_be_boolean")

        payload = super()._request_payload(messages, temperature, max_tokens, **kwargs)
        payload.update(
            {
                "enable_thinking": enable_thinking,
                "stream": False,
                "reasoning_effort": reasoning_effort,
            }
        )

        tools = kwargs.get("tools")
        if tools is not None:
            if not isinstance(tools, list):
                raise ValueError("dotin_tools_must_be_array")
            payload["tools"] = tools

        tool_choice = kwargs.get("tool_choice")
        if tool_choice is not None:
            if not isinstance(tool_choice, (str, dict)):
                raise ValueError("invalid_dotin_tool_choice")
            if isinstance(tool_choice, str) and tool_choice not in {"none", "auto", "required"}:
                raise ValueError("invalid_dotin_tool_choice")
            payload["tool_choice"] = tool_choice

        return payload


def configured_llm_adapter() -> LLMAdapter:
    provider = settings.LLM_PROVIDER.strip().lower()
    if provider == "mock":
        if settings.APP_ENV == "production":
            raise RuntimeError("mock_llm_provider_forbidden_in_production")
        from integrations.llm.mock_provider import MockLLMProvider

        return MockLLMProvider()
    if provider in {"dotin-general-chatbot", "dotin_general_chatbot"}:
        if not settings.LLM_BASE_URL:
            raise RuntimeError("LLM_BASE_URL is required")
        if not settings.LLM_API_KEY:
            raise RuntimeError("LLM_API_KEY is required for Dotin General Chatbot")
        return DotinGeneralChatbotLLMProvider(
            settings.LLM_BASE_URL,
            settings.LLM_MODEL,
            settings.LLM_API_KEY,
        )
    if provider in {"openai-compatible", "openai_compatible"}:
        if not settings.LLM_BASE_URL:
            raise RuntimeError("LLM_BASE_URL is required")
        return OpenAICompatibleLLMProvider(settings.LLM_BASE_URL, settings.LLM_MODEL, settings.LLM_API_KEY)
    raise RuntimeError(f"unsupported_llm_provider:{provider}")
