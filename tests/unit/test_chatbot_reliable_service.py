import pytest
from fastapi import HTTPException

from apps.chatbot.models import ChatMessageRequest
from apps.chatbot.reliable_service import (
    OperationsCopilotService,
    ReliableChatLLMAdapter,
    _looks_obviously_incomplete,
)
from apps.chatbot.service import ChatbotService
from apps.security.oidc import Identity
from integrations.llm.base import LLMAdapter, LLMResponse


class SequencedLLM(LLMAdapter):
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    @property
    def provider_name(self):
        return "sequenced"

    async def generate(self, prompt, system_prompt=None, temperature=0.7, max_tokens=1000, **kwargs):
        self.calls.append(("generate", max_tokens, kwargs))
        value = self.responses.pop(0)
        if isinstance(value, Exception):
            raise value
        return value

    async def generate_with_messages(self, messages, temperature=0.7, max_tokens=1000, **kwargs):
        self.calls.append(("messages", max_tokens, kwargs, list(messages)))
        value = self.responses.pop(0)
        if isinstance(value, Exception):
            raise value
        return value


def response(content, *, tool_calls=None):
    return LLMResponse(content=content, model="test", tool_calls=tool_calls, finish_reason="stop")


def test_direct_chat_incomplete_detector_is_conservative():
    assert _looks_obviously_incomplete(response("سرویس **haproxy** روی سر")) is True
    assert _looks_obviously_incomplete(response("بله.")) is False
    assert _looks_obviously_incomplete(response("nginx روی 10.100.6.199 فعال است.")) is False
    assert _looks_obviously_incomplete(
        response("", tool_calls=[{"function": {"name": "vm_metrics", "arguments": "{}"}}])
    ) is False


@pytest.mark.asyncio
async def test_chatbot_intent_retries_one_incomplete_direct_answer_before_persistence():
    delegate = SequencedLLM([
        response("سرویس **haproxy** روی سر"),
        response("سرویس **haproxy** روی سرور 10.100.6.199 فعال و در حال اجراست."),
    ])
    adapter = ReliableChatLLMAdapter(delegate)
    result = await adapter.generate_with_messages(
        [{"role": "user", "content": "haproxy چی؟"}],
        max_tokens=100,
        stage="chatbot_intent",
        tools=[{"type": "function", "function": {"name": "vm_service_status"}}],
        tool_choice="auto",
    )
    assert "10.100.6.199" in result.content
    assert len(delegate.calls) == 2
    assert delegate.calls[0][1] == 100
    assert delegate.calls[1][1] == 200
    assert "RETRY REQUIRED" in delegate.calls[1][3][-1]["content"]


@pytest.mark.asyncio
async def test_chatbot_intent_fails_closed_after_bounded_incomplete_retry():
    delegate = SequencedLLM([response("پاسخ نصفه"), response("هنوز نصفه")])
    adapter = ReliableChatLLMAdapter(delegate)
    with pytest.raises(ValueError, match="chatbot_llm_incomplete_response"):
        await adapter.generate_with_messages(
            [{"role": "user", "content": "وضعیت؟"}],
            max_tokens=80,
            stage="chatbot_intent",
        )
    assert len(delegate.calls) == 2


@pytest.mark.asyncio
async def test_non_chatbot_stage_does_not_add_chat_repair_semantics():
    delegate = SequencedLLM([response("partial")])
    adapter = ReliableChatLLMAdapter(delegate)
    result = await adapter.generate_with_messages(
        [{"role": "user", "content": "triage"}],
        stage="triage",
    )
    assert result.content == "partial"
    assert len(delegate.calls) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("base_detail", "cause", "expected_status", "expected_detail"),
    [
        ("chatbot_llm_unavailable", TimeoutError("provider timed out"), 504, "chatbot_llm_timeout"),
        (
            "chatbot_llm_unavailable",
            ValueError("chatbot_llm_incomplete_response"),
            503,
            "chatbot_llm_incomplete_response",
        ),
        ("chatbot_tool_failed:vm_metrics", TimeoutError("mcp timed out"), 504, "chatbot_tool_timeout:vm_metrics"),
        (
            "chatbot_tool_failed:vm_metrics",
            ConnectionError("mcp connection refused"),
            502,
            "chatbot_tool_unavailable:vm_metrics",
        ),
    ],
)
async def test_operations_copilot_preserves_safe_failure_cause_taxonomy(
    monkeypatch,
    base_detail,
    cause,
    expected_status,
    expected_detail,
):
    async def fail_closed_base_message(self, identity, request):
        raise HTTPException(status_code=503, detail=base_detail) from cause

    monkeypatch.setattr(ChatbotService, "message", fail_closed_base_message)
    service = OperationsCopilotService()
    identity = Identity(subject="test", roles=("viewer",))
    with pytest.raises(HTTPException) as failure:
        await service.message(identity, ChatMessageRequest(message="status?"))
    assert failure.value.status_code == expected_status
    assert failure.value.detail == expected_detail
