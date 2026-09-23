import pytest

from apps.chatbot.governance import (
    build_evidence,
    deterministic_validation,
    is_knowledge_question,
    missing_capability_message,
    requires_live_evidence,
)
from apps.chatbot.reliable_service import ReliableChatLLMAdapter
from integrations.llm.base import LLMAdapter, LLMResponse


class SequencedLLM(LLMAdapter):
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    @property
    def provider_name(self):
        return "test"

    async def generate(self, prompt, system_prompt=None, temperature=0.7, max_tokens=1000, **kwargs):
        self.calls.append(("generate", prompt, kwargs))
        return self.responses.pop(0)

    async def generate_with_messages(self, messages, temperature=0.7, max_tokens=1000, **kwargs):
        self.calls.append(("messages", list(messages), kwargs))
        return self.responses.pop(0)


def llm_response(content="", tool_calls=None):
    return LLMResponse(
        content=content,
        model="test",
        tool_calls=tool_calls,
        finish_reason="tool_calls" if tool_calls else "stop",
    )


def test_live_evidence_classifier_separates_knowledge_from_current_state():
    assert is_knowledge_question("OOMKilled چیست؟") is True
    assert requires_live_evidence("OOMKilled چیست؟") is False
    assert requires_live_evidence("وضعیت nginx روی 10.100.6.199 چیه؟") is True
    assert requires_live_evidence("/app چقدر فضا داره؟") is True
    assert requires_live_evidence("why is nginx not starting on 10.100.6.199?") is True


def test_deterministic_validator_rejects_operational_answer_without_evidence():
    verdict = deterministic_validation(
        question="CPU سرور 10.100.6.199 چقدره؟",
        answer="CPU is 12%.",
        evidence=[],
    )
    assert verdict.valid is False
    assert verdict.needs_replan is True
    assert verdict.claims_grounded is False
    assert verdict.confidence == 0.0


def test_deterministic_validator_accepts_grounded_operational_answer():
    evidence = build_evidence(
        source="vm_mcp",
        tool="vm_metrics",
        target="10.100.6.199",
        data={"cpu_percent": 12.0},
    )
    verdict = deterministic_validation(
        question="CPU سرور 10.100.6.199 چقدره؟",
        answer="CPU is 12%.",
        evidence=[evidence],
    )
    assert verdict.valid is True
    assert verdict.evidence_sufficient is True
    assert verdict.claims_grounded is True
    assert verdict.confidence >= 0.70


@pytest.mark.asyncio
async def test_live_question_without_tool_is_replanned_once_and_selects_tool():
    tool_call = {
        "function": {
            "name": "vm_service_status",
            "arguments": '{"target":"10.100.6.199","service":"nginx"}',
        }
    }
    delegate = SequencedLLM(
        [
            llm_response("nginx is probably running."),
            llm_response("", tool_calls=[tool_call]),
        ]
    )
    adapter = ReliableChatLLMAdapter(delegate)

    result = await adapter.generate_with_messages(
        [{"role": "user", "content": "وضعیت nginx روی 10.100.6.199 چیه؟"}],
        stage="chatbot_intent",
        tools=[{"type": "function", "function": {"name": "vm_service_status"}}],
        tool_choice="auto",
    )

    assert result.tool_calls == [tool_call]
    assert len(delegate.calls) == 2
    assert "REPLAN REQUIRED" in delegate.calls[1][1][-1]["content"]


@pytest.mark.asyncio
async def test_live_question_without_available_tool_returns_safe_missing_capability():
    delegate = SequencedLLM(
        [
            llm_response("I think it is healthy."),
            llm_response("I cannot call a tool."),
        ]
    )
    adapter = ReliableChatLLMAdapter(delegate)

    result = await adapter.generate_with_messages(
        [{"role": "user", "content": "CPU سرور 10.100.6.199 چقدره؟"}],
        stage="chatbot_intent",
        tools=[],
        tool_choice="auto",
    )

    assert result.tool_calls is None
    assert result.content == missing_capability_message("CPU سرور 10.100.6.199 چقدره؟")
    assert "حدس" in result.content


@pytest.mark.asyncio
async def test_explicit_cognia_write_is_replanned_to_write_tool():
    tool_call = {
        "function": {
            "name": "cognia_register_knowledge",
            "arguments": '{"title":"Nginx recovery","content":"validated steps"}',
        }
    }
    delegate = SequencedLLM(
        [
            llm_response("باشه، در Cognia ذخیره می‌کنم."),
            llm_response("", tool_calls=[tool_call]),
        ]
    )
    adapter = ReliableChatLLMAdapter(delegate)

    result = await adapter.generate_with_messages(
        [{"role": "user", "content": "این اطلاعات را در Cognia ذخیره کن"}],
        stage="chatbot_intent",
        tools=[{"type": "function", "function": {"name": "cognia_register_knowledge"}}],
        tool_choice="auto",
    )

    assert result.tool_calls == [tool_call]
    assert len(delegate.calls) == 2
    assert "Cognia knowledge write" in delegate.calls[1][1][-1]["content"]
