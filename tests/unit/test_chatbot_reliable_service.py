import pytest

from apps.chatbot.reliable_service import ReliableChatLLMAdapter, _looks_obviously_incomplete
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
