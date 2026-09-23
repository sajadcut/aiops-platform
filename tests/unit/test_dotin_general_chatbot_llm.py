from __future__ import annotations

import httpx
import pytest

from domain.contracts.config import settings
from integrations.llm import openai_compatible as llm_module
from integrations.llm.openai_compatible import (
    DotinGeneralChatbotLLMProvider,
    configured_llm_adapter,
)


class FakeResponse:
    def __init__(self, payload, status_code=200):
        self._payload = payload
        self.status_code = status_code

    def raise_for_status(self):
        if self.status_code >= 400:
            request = httpx.Request("POST", "https://llm.example/v1/chat/completions")
            response = httpx.Response(self.status_code, request=request)
            raise httpx.HTTPStatusError(
                f"HTTP {self.status_code}",
                request=request,
                response=response,
            )
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

class SequenceClient:
    def __init__(self, recorder, responses):
        self.recorder = recorder
        self.responses = responses

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    async def post(self, url, *, headers, json):
        self.recorder.setdefault("calls", []).append(
            {"url": url, "headers": dict(headers), "json": dict(json)}
        )
        item = self.responses.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


def _install_sequence_client(monkeypatch, recorder, responses):
    sequence = list(responses)

    def factory(**kwargs):
        recorder.setdefault("client_kwargs", []).append(dict(kwargs))
        return SequenceClient(recorder, sequence)

    monkeypatch.setattr(llm_module, "insecure_async_client", factory)


@pytest.mark.asyncio
async def test_dotin_provider_retries_transient_500_then_succeeds(monkeypatch):
    recorder = {}
    monkeypatch.setattr(settings, "RETRY_MAX_ATTEMPTS", 3)
    monkeypatch.setattr(settings, "RETRY_DELAY_SECONDS", 0.0)
    monkeypatch.setattr(settings, "RETRY_BACKOFF_FACTOR", 2.0)
    _install_sequence_client(
        monkeypatch,
        recorder,
        [
            FakeResponse({"error": "temporary"}, status_code=500),
            FakeResponse(
                {
                    "choices": [
                        {
                            "finish_reason": "stop",
                            "message": {"role": "assistant", "content": "recovered"},
                        }
                    ],
                    "model": "assistance-model",
                },
                status_code=200,
            ),
        ],
    )
    provider = DotinGeneralChatbotLLMProvider(
        "https://aifa-chatbot.dev.dotin.ir",
        "assistance-model",
        "secret-token",
    )

    result = await provider.generate_with_messages(
        [{"role": "user", "content": "status?"}],
        request_id="retry-500",
    )

    assert result.content == "recovered"
    assert len(recorder["calls"]) == 2
    assert {call["headers"]["x-request-id"] for call in recorder["calls"]} == {"retry-500"}


@pytest.mark.asyncio
async def test_dotin_provider_does_not_retry_nontransient_400(monkeypatch):
    recorder = {}
    monkeypatch.setattr(settings, "RETRY_MAX_ATTEMPTS", 3)
    monkeypatch.setattr(settings, "RETRY_DELAY_SECONDS", 0.0)
    _install_sequence_client(
        monkeypatch,
        recorder,
        [FakeResponse({"error": "bad request"}, status_code=400)],
    )
    provider = DotinGeneralChatbotLLMProvider(
        "https://aifa-chatbot.dev.dotin.ir",
        "assistance-model",
        "secret-token",
    )

    with pytest.raises(httpx.HTTPStatusError):
        await provider.generate_with_messages(
            [{"role": "user", "content": "invalid"}],
            request_id="no-retry-400",
        )

    assert len(recorder["calls"]) == 1


@pytest.mark.asyncio
async def test_dotin_provider_retries_transport_error_then_succeeds(monkeypatch):
    recorder = {}
    monkeypatch.setattr(settings, "RETRY_MAX_ATTEMPTS", 2)
    monkeypatch.setattr(settings, "RETRY_DELAY_SECONDS", 0.0)
    _install_sequence_client(
        monkeypatch,
        recorder,
        [
            httpx.ConnectError(
                "temporary",
                request=httpx.Request("POST", "https://llm.example/v1/chat/completions"),
            ),
            FakeResponse(
                {
                    "choices": [
                        {
                            "finish_reason": "stop",
                            "message": {"role": "assistant", "content": "ok-after-connect-error"},
                        }
                    ],
                    "model": "assistance-model",
                }
            ),
        ],
    )
    provider = DotinGeneralChatbotLLMProvider(
        "https://aifa-chatbot.dev.dotin.ir",
        "assistance-model",
        "secret-token",
    )

    result = await provider.generate_with_messages(
        [{"role": "user", "content": "status?"}],
        request_id="retry-connect",
    )

    assert result.content == "ok-after-connect-error"
    assert len(recorder["calls"]) == 2

