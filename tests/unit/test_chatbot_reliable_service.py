import pytest
from fastapi import HTTPException

from apps.chatbot.errors import classify_chatbot_error
from apps.chatbot.models import ChatMessageRequest
from apps.chatbot.reliable_service import (
    OperationsCopilotService,
    ReliableChatLLMAdapter,
    _looks_obviously_incomplete,
    _requires_live_operational_tool,
)
from apps.chatbot.service import ChatbotService, _SUMMARY_SYSTEM_PROMPT, _annotate_metric_units
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
        (
            "chatbot_tool_failed:vm_service_status",
            RuntimeError("vm_target_not_allowed"),
            403,
            "chatbot_target_not_allowed:vm_service_status",
        ),
        (
            "chatbot_tool_failed:vm_service_status",
            RuntimeError("vm_service_not_allowed"),
            403,
            "chatbot_service_not_allowed:vm_service_status",
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

@pytest.mark.asyncio
async def test_chatbot_intent_retries_tool_free_operational_check_preamble():
    tool_call = {
        "id": "call-status",
        "type": "function",
        "function": {
            "name": "vm_service_status",
            "arguments": '{"target":"10.100.6.200","service":"nginx"}',
        },
    }
    delegate = SequencedLLM([
        response(
            "برای بررسی وضعیت سرویس nginx روی سرور 10.100.6.200، ابتدا وضعیت سرویس "
            "و سپس منابع سرور را بررسی می‌کنم."
        ),
        response("", tool_calls=[tool_call]),
    ])
    adapter = ReliableChatLLMAdapter(delegate)

    result = await adapter.generate_with_messages(
        [
            {"role": "user", "content": "nginx سرور 10.100.6.199 در چه وضعیته"},
            {"role": "assistant", "content": "سرویس nginx روی 10.100.6.199 غیرفعال است."},
            {"role": "user", "content": "6.200چی"},
        ],
        max_tokens=120,
        stage="chatbot_intent",
        tools=[{"type": "function", "function": {"name": "vm_service_status"}}],
        tool_choice="auto",
    )

    assert result.tool_calls == [tool_call]
    assert len(delegate.calls) == 2
    repair = delegate.calls[1][3][-1]["content"]
    assert "select the tool now" in repair
    assert "future check" in repair


@pytest.mark.asyncio
async def test_chatbot_intent_fails_closed_when_tool_preamble_repeats():
    delegate = SequencedLLM([
        response("برای بررسی وضعیت سرور، ابتدا وضعیت سرویس را بررسی می‌کنم."),
        response("ابتدا وضعیت سرویس را چک می‌کنم و سپس منابع را بررسی می‌کنم."),
    ])
    adapter = ReliableChatLLMAdapter(delegate)

    with pytest.raises(ValueError, match="chatbot_llm_incomplete_response"):
        await adapter.generate_with_messages(
            [{"role": "user", "content": "6.200چی"}],
            max_tokens=120,
            stage="chatbot_intent",
            tools=[{"type": "function", "function": {"name": "vm_service_status"}}],
            tool_choice="auto",
        )

    assert len(delegate.calls) == 2


@pytest.mark.asyncio
async def test_direct_nonoperational_future_statement_is_not_forced_to_tool():
    delegate = SequencedLLM([
        response("اگر بخواهید، بعداً می‌توانم این معماری را هم توضیح بدهم."),
    ])
    adapter = ReliableChatLLMAdapter(delegate)

    result = await adapter.generate_with_messages(
        [{"role": "user", "content": "MCP یعنی چه؟"}],
        max_tokens=120,
        stage="chatbot_intent",
        tools=[{"type": "function", "function": {"name": "vm_service_status"}}],
        tool_choice="auto",
    )

    assert "معماری" in result.content
    assert len(delegate.calls) == 1

@pytest.mark.asyncio
async def test_chatbot_live_followup_rejects_tool_free_fabricated_status():
    tool_call = {
        "id": "call-live-status",
        "type": "function",
        "function": {
            "name": "vm_service_status",
            "arguments": '{"target":"10.100.6.200","service":"nginx"}',
        },
    }
    delegate = SequencedLLM([
        response("nginx روی 10.100.6.200 فعال و healthy است."),
        response("", tool_calls=[tool_call]),
    ])
    adapter = ReliableChatLLMAdapter(delegate)

    result = await adapter.generate_with_messages(
        [
            {"role": "user", "content": "nginx سرور 10.100.6.199 در چه وضعیته"},
            {"role": "assistant", "content": "nginx روی 10.100.6.199 inactive است."},
            {"role": "user", "content": "6.200چی"},
        ],
        max_tokens=120,
        stage="chatbot_intent",
        tools=[{"type": "function", "function": {"name": "vm_service_status"}}],
        tool_choice="auto",
    )

    assert result.tool_calls == [tool_call]
    assert len(delegate.calls) == 2


@pytest.mark.asyncio
async def test_chatbot_live_request_fails_closed_if_model_refuses_tool_twice():
    delegate = SequencedLLM([
        response("CPU سرور 10.100.6.200 حدود 10 درصد است."),
        response("CPU سرور 10.100.6.200 حدود 11 درصد است."),
    ])
    adapter = ReliableChatLLMAdapter(delegate)

    with pytest.raises(ValueError, match="chatbot_llm_incomplete_response"):
        await adapter.generate_with_messages(
            [{"role": "user", "content": "cpu سرور 10.100.6.200 چقدره"}],
            max_tokens=120,
            stage="chatbot_intent",
            tools=[{"type": "function", "function": {"name": "vm_metrics"}}],
            tool_choice="auto",
        )

    assert len(delegate.calls) == 2

def test_chatbot_vm_allowlist_denials_are_operator_safe_and_non_retryable():
    target = classify_chatbot_error(
        HTTPException(status_code=403, detail="chatbot_target_not_allowed:vm_service_status")
    )
    service = classify_chatbot_error(
        HTTPException(status_code=403, detail="chatbot_service_not_allowed:vm_service_status")
    )

    assert target.code == "VM_TARGET_NOT_ALLOWED"
    assert target.component == "authorization"
    assert target.retryable is False
    assert "SSH_ALLOWED_TARGETS" in target.message

    assert service.code == "VM_SERVICE_NOT_ALLOWED"
    assert service.component == "authorization"
    assert service.retryable is False
    assert "SSH_ALLOWED_SERVICES" in service.message

def test_live_inspection_classifier_covers_service_check_with_partial_target_context():
    messages = [
        {"role": "user", "content": "وضعیت سرور 10.100.6.199 بگو"},
        {"role": "assistant", "content": "وضعیت از ابزارهای live خوانده شد."},
        {"role": "user", "content": "haproxy 6.199 بررسی کن"},
    ]
    assert _requires_live_operational_tool(messages, tools_available=True) is True


def test_live_inspection_classifier_does_not_force_generic_architecture_review():
    messages = [{"role": "user", "content": "این معماری را بررسی کن"}]
    assert _requires_live_operational_tool(messages, tools_available=True) is False


@pytest.mark.asyncio
async def test_live_inspection_repair_requires_structured_tool_choice():
    tool_call = {
        "id": "call-haproxy",
        "type": "function",
        "function": {
            "name": "vm_service_status",
            "arguments": '{"target":"10.100.6.199","service":"haproxy"}',
        },
    }
    delegate = SequencedLLM([
        response("Service is not in the read allowlist: haproxy."),
        response("", tool_calls=[tool_call]),
    ])
    adapter = ReliableChatLLMAdapter(delegate)

    result = await adapter.generate_with_messages(
        [
            {"role": "user", "content": "وضعیت سرور 10.100.6.199 بگو"},
            {"role": "assistant", "content": "live result"},
            {"role": "user", "content": "haproxy 6.199 بررسی کن"},
        ],
        max_tokens=120,
        stage="chatbot_intent",
        tools=[{"type": "function", "function": {"name": "vm_service_status"}}],
        tool_choice="auto",
    )

    assert result.tool_calls == [tool_call]
    assert len(delegate.calls) == 2
    assert delegate.calls[1][2]["tool_choice"] == "required"


def test_vm_metric_summary_contract_preserves_percentage_points_exactly():
    payload = {
        "source": "vm_mcp",
        "result": {
            "metrics": {
                "cpu_usage": 0.74,
                "memory_usage": 8.14,
                "swap_usage": 0.0,
                "io_wait": 0.0,
                "load_avg": "0.01,0.01,0.00",
            }
        },
    }
    annotated = _annotate_metric_units(payload)

    assert annotated["result"]["metrics"]["cpu_usage"] == {
        "value": 0.74,
        "unit": "percent",
        "display": "0.74%",
    }
    assert annotated["result"]["metrics"]["memory_usage"]["display"] == "8.14%"
    assert annotated["result"]["metrics"]["load_avg"] == "0.01,0.01,0.00"
    assert "cpu_usage=0.74 means 0.74%, never 74%" in _SUMMARY_SYSTEM_PROMPT

