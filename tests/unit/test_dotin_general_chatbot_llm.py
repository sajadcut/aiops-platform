from __future__ import annotations

import pytest

from domain.contracts.config import settings
from integrations.llm import openai_compatible as llm_module
from integrations.llm.openai_compatible import (
    DotinGeneralChatbotLLMProvider,
    configured_llm_adapter,
)


class FakeResponse:
    def __init__(self, payload):
        self._payload = payload

    def raise_for_status(self):
        return None

    def json(self):
        return self._payload


class FakeClient:
    def __init__(self, recorder, payload):
        self.recorder = recorder
        self.payload = payload

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    async def post(self, url, *, headers, json):
        self.recorder["url"] = url
        self.recorder["headers"] = dict(headers)
        self.recorder["json"] = dict(json)
        return FakeResponse(self.payload)


def _install_fake_client(monkeypatch, recorder, payload):
    def factory(**kwargs):
        recorder["client_kwargs"] = dict(kwargs)
        return FakeClient(recorder, payload)

    monkeypatch.setattr(llm_module, "insecure_async_client", factory)


@pytest.mark.asyncio
async def test_dotin_provider_uses_documented_endpoint_headers_and_defaults(monkeypatch):
    recorder = {}
    _install_fake_client(
        monkeypatch,
        recorder,
        {
            "id": "chatcmpl-1",
            "choices": [
                {
                    "finish_reason": "stop",
                    "index": 0,
                    "message": {"role": "assistant", "content": "ok"},
                }
            ],
            "model": "assistance-model",
            "usage": {"prompt_tokens": 10, "completion_tokens": 2, "total_tokens": 12},
        },
    )
    provider = DotinGeneralChatbotLLMProvider(
        "https://aifa-chatbot.dev.dotin.ir",
        "assistance-model",
        "secret-token",
    )

    result = await provider.generate(
        "status?",
        request_id="req-123",
        session_id="incident-456",
        user_id="aiops-service",
    )

    assert provider.provider_name == "dotin-general-chatbot"
    assert recorder["url"] == "https://aifa-chatbot.dev.dotin.ir/v1/chat/completions"
    assert recorder["headers"] == {
        "Authorization": "Bearer secret-token",
        "Content-Type": "application/json",
        "x-request-id": "req-123",
        "x-session-id": "incident-456",
        "x-user-id": "aiops-service",
    }
    assert recorder["json"]["model"] == "assistance-model"
    assert recorder["json"]["messages"] == [{"role": "user", "content": "status?"}]
    assert recorder["json"]["enable_thinking"] is False
    assert recorder["json"]["stream"] is False
    assert recorder["json"]["reasoning_effort"] == "medium"
    assert result.content == "ok"
    assert result.finish_reason == "stop"
    assert result.tool_calls is None


@pytest.mark.asyncio
async def test_dotin_provider_preserves_documented_tool_call_response(monkeypatch):
    recorder = {}
    tool_call = {
        "type": "function",
        "function": {"name": "search_docs", "arguments": "{}"},
        "id": "tool-1",
    }
    _install_fake_client(
        monkeypatch,
        recorder,
        {
            "id": "chatcmpl-2",
            "choices": [
                {
                    "finish_reason": "tool_calls",
                    "index": 0,
                    "message": {"role": "assistant", "content": "", "tool_calls": [tool_call]},
                }
            ],
            "model": "developer-model",
            "usage": {"prompt_tokens": 20, "completion_tokens": 5, "total_tokens": 25},
        },
    )
    provider = DotinGeneralChatbotLLMProvider(
        "https://aifa-chatbot.dev.dotin.ir/v1",
        "developer-model",
        "secret-token",
    )
    tools = [
        {
            "type": "function",
            "function": {
                "name": "search_docs",
                "description": "Search governed docs",
                "parameters": {"type": "object", "properties": {}, "required": []},
            },
        }
    ]

    result = await provider.generate_with_messages(
        [{"role": "user", "content": "find the runbook"}],
        tools=tools,
        tool_choice={
            "type": "allowed_tools",
            "mode": "auto",
            "tools": [{"type": "function", "name": "search_docs"}],
        },
        enable_thinking=True,
        reasoning_effort="xhigh",
    )

    assert recorder["url"] == "https://aifa-chatbot.dev.dotin.ir/v1/chat/completions"
    assert recorder["json"]["tools"] == tools
    assert recorder["json"]["tool_choice"]["type"] == "allowed_tools"
    assert recorder["json"]["enable_thinking"] is True
    assert recorder["json"]["reasoning_effort"] == "xhigh"
    assert result.content == ""
    assert result.finish_reason == "tool_calls"
    assert result.tool_calls == [tool_call]


def test_dotin_provider_validates_documented_model_and_request_options():
    with pytest.raises(ValueError, match="dotin_llm_model"):
        DotinGeneralChatbotLLMProvider("https://llm.example", "gpt-4", "token")
    with pytest.raises(ValueError, match="bearer_token_required"):
        DotinGeneralChatbotLLMProvider("https://llm.example", "assistance-model", None)

    provider = DotinGeneralChatbotLLMProvider(
        "https://llm.example",
        "assistance-model",
        "token",
    )
    messages = [{"role": "user", "content": "hello"}]
    with pytest.raises(ValueError, match="invalid_dotin_reasoning_effort"):
        provider._request_payload(messages, 0.2, 100, reasoning_effort="ultra")
    with pytest.raises(ValueError, match="streaming_not_supported"):
        provider._request_payload(messages, 0.2, 100, stream=True)
    with pytest.raises(ValueError, match="invalid_dotin_tool_choice"):
        provider._request_payload(messages, 0.2, 100, tool_choice="sometimes")


def test_configured_llm_adapter_selects_dotin_provider(monkeypatch):
    monkeypatch.setattr(settings, "LLM_PROVIDER", "dotin-general-chatbot")
    monkeypatch.setattr(settings, "LLM_BASE_URL", "https://aifa-chatbot.dev.dotin.ir")
    monkeypatch.setattr(settings, "LLM_MODEL", "assistance-model")
    monkeypatch.setattr(settings, "LLM_API_KEY", "token")

    adapter = configured_llm_adapter()

    assert isinstance(adapter, DotinGeneralChatbotLLMProvider)
    assert adapter.chat_endpoint.endswith("/v1/chat/completions")
