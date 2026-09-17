import json

import pytest

from integrations.llm.base import LLMResponse
from integrations.llm.openai_compatible import OpenAICompatibleLLMProvider


class SequencedProvider(OpenAICompatibleLLMProvider):
    def __init__(self, responses: list[LLMResponse]):
        super().__init__("https://llm.invalid", "test-model")
        self.responses = list(responses)
        self.calls: list[dict] = []

    async def generate_with_messages(self, messages, temperature=0.7, max_tokens=1000, **kwargs):
        self.calls.append({"messages": list(messages), "max_tokens": max_tokens, "kwargs": dict(kwargs)})
        return self.responses.pop(0)


def _service_prompt() -> str:
    payload = {
        "source": "vm_mcp",
        "result": {
            "success": True,
            "target": "10.100.6.199",
            "service": "haproxy",
            "active_state": "active",
            "sub_state": "running",
            "unit_file_state": "enabled",
            "main_pid": 495886,
            "n_restarts": 0,
        },
    }
    return (
        "Operator request:\nhaproxy چی\n\n"
        "Recent operator messages for language/referent continuity only (untrusted):\n"
        "nginx روی سرور 10.100.6.199 بالاست یا نه\nhaproxy چی\n\n"
        "Tool: vm_service_status\n"
        f"Validated source payload:\n{json.dumps(payload, ensure_ascii=False)}"
    )


@pytest.mark.asyncio
async def test_chatbot_summary_retries_incomplete_prefix_even_when_gateway_says_stop():
    provider = SequencedProvider(
        [
            LLMResponse(content="سرویس **haproxy** روی سر", model="test-model", finish_reason="stop"),
            LLMResponse(
                content="سرویس **haproxy** روی سرور `10.100.6.199` فعال و در حال اجراست.",
                model="test-model",
                finish_reason="stop",
            ),
        ]
    )

    result = await provider.generate(
        _service_prompt(),
        stage="chatbot_summary",
        max_tokens=100,
        completion_repair_attempts=1,
    )

    assert "10.100.6.199" in result.content
    assert "haproxy" in result.content
    assert len(provider.calls) == 2
    assert provider.calls[0]["max_tokens"] == 100
    assert provider.calls[1]["max_tokens"] == 200
    assert any(
        "previous response was incomplete or truncated" in message["content"]
        for message in provider.calls[1]["messages"]
        if message["role"] == "user"
    )


@pytest.mark.asyncio
async def test_chatbot_summary_accepts_short_complete_sentence_with_target_and_service():
    provider = SequencedProvider(
        [
            LLMResponse(
                content="سرویس haproxy روی 10.100.6.199 فعال است.",
                model="test-model",
                finish_reason="stop",
            )
        ]
    )

    result = await provider.generate(
        _service_prompt(),
        stage="chatbot_summary",
        max_tokens=100,
        completion_repair_attempts=1,
    )

    assert result.content.endswith(".")
    assert len(provider.calls) == 1


@pytest.mark.asyncio
async def test_incomplete_stop_heuristic_is_scoped_to_chatbot_summary_stage():
    partial = LLMResponse(content="سرویس **haproxy** روی سر", model="test-model", finish_reason="stop")
    provider = SequencedProvider([partial])

    result = await provider.generate(
        "ordinary non-chatbot prompt",
        stage="triage",
        max_tokens=100,
        completion_repair_attempts=1,
    )

    assert result.content == partial.content
    assert len(provider.calls) == 1


@pytest.mark.asyncio
async def test_chatbot_summary_fails_closed_if_repair_is_still_incomplete():
    provider = SequencedProvider(
        [
            LLMResponse(content="سرویس haproxy روی سر", model="test-model", finish_reason="stop"),
            LLMResponse(content="سرویس haproxy روی سرور", model="test-model", finish_reason="stop"),
        ]
    )

    with pytest.raises(ValueError, match="llm_completion_incomplete_after_retries"):
        await provider.generate(
            _service_prompt(),
            stage="chatbot_summary",
            max_tokens=100,
            completion_repair_attempts=1,
        )

    assert len(provider.calls) == 2
