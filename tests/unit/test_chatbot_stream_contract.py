import json
from uuid import uuid4

import pytest

from apps.chatbot.models import ChatMessageRequest, ChatMessageResponse
from apps.chatbot.streaming import _chunks, _event_stream, _sse
from apps.security.oidc import Identity


def _parse_event(frame: bytes):
    text = frame.decode("utf-8")
    event = next(line[7:] for line in text.splitlines() if line.startswith("event: "))
    data = next(line[6:] for line in text.splitlines() if line.startswith("data: "))
    return event, json.loads(data)


def test_sse_encoder_is_utf8_json_and_chunks_preserve_text():
    frame = _sse("delta", {"text": "سلام nginx"})
    event, payload = _parse_event(frame)
    assert event == "delta"
    assert payload == {"text": "سلام nginx"}
    original = "این یک پاسخ فارسی همراه با nginx و 10.100.6.199 است."
    assert "".join(_chunks(original, 7)) == original


class SuccessfulService:
    async def message(self, identity, request):
        return ChatMessageResponse(
            session_id=request.session_id,
            kind="tool_result",
            message="nginx روی 10.100.6.199 فعال است.",
            tool="vm_service_status",
            source="vm_mcp",
            data={"active": True},
        )


class FailedService:
    async def message(self, identity, request):
        from fastapi import HTTPException
        raise HTTPException(status_code=503, detail="chatbot_llm_unavailable")


@pytest.mark.asyncio
async def test_every_successful_stream_has_terminal_complete_event():
    request = ChatMessageRequest(session_id=uuid4(), message="nginx بالاست؟")
    events = []
    async for frame in _event_stream(
        SuccessfulService(),
        Identity(subject="test", roles=("viewer",)),
        request,
        request_id="req-1",
    ):
        events.append(_parse_event(frame))
    names = [name for name, _ in events]
    assert names[0:2] == ["session", "status"]
    assert "answer_start" in names
    assert "delta" in names
    assert names[-1] == "complete"
    assert events[-1][1]["request_id"] == "req-1"


@pytest.mark.asyncio
async def test_failed_stream_emits_short_terminal_error_instead_of_ending_silently(monkeypatch):
    async def no_persist(*args, **kwargs):
        return None

    monkeypatch.setattr("apps.chatbot.streaming._persist_terminal_error", no_persist)
    request = ChatMessageRequest(session_id=uuid4(), message="cpu چقدره؟")
    events = []
    async for frame in _event_stream(
        FailedService(),
        Identity(subject="test", roles=("viewer",)),
        request,
        request_id="req-2",
    ):
        events.append(_parse_event(frame))
    assert events[-1][0] == "error"
    assert events[-1][1]["code"] == "LLM_UNAVAILABLE"
    assert events[-1][1]["message"] == "LLM پاسخ نداد. دوباره تلاش کنید."
    assert "chatbot_llm_unavailable" not in events[-1][1]["message"]
