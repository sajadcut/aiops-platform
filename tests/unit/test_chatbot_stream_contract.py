import asyncio
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


class BlockingService:
    def __init__(self):
        self.started = asyncio.Event()
        self.cancelled = asyncio.Event()

    async def message(self, identity, request):
        self.started.set()
        try:
            await asyncio.Event().wait()
        finally:
            self.cancelled.set()


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


@pytest.mark.asyncio
async def test_early_stream_close_cancels_inflight_work_and_persists_terminal_state(monkeypatch):
    persisted = []

    async def record_persist(session_id, **kwargs):
        persisted.append((str(session_id), kwargs))

    monkeypatch.setattr("apps.chatbot.streaming._persist_terminal_error", record_persist)
    service = BlockingService()
    request = ChatMessageRequest(session_id=uuid4(), message="وضعیت nginx را بررسی کن")
    stream = _event_stream(
        service,
        Identity(subject="test", roles=("viewer",)),
        request,
        request_id="req-interrupted",
    )

    first_event = _parse_event(await anext(stream))
    assert first_event[0] == "session"
    await asyncio.wait_for(service.started.wait(), timeout=1.0)

    # Simulate the HTTP client disappearing while the generator is suspended on
    # the very first SSE frame. This used to bypass the interruption handler.
    await stream.aclose()
    await asyncio.wait_for(service.cancelled.wait(), timeout=1.0)

    assert len(persisted) == 1
    session_id, terminal = persisted[0]
    assert session_id == str(request.session_id)
    assert terminal["code"] == "REQUEST_INTERRUPTED"
    assert terminal["component"] == "chat"
    assert terminal["retryable"] is True
    assert "متوقف شد" in terminal["message"]
