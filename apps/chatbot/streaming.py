from __future__ import annotations

import asyncio
import json
import time
from collections.abc import AsyncIterator
from typing import Any
from uuid import UUID

from fastapi.responses import StreamingResponse
from prometheus_client import Counter, Histogram

from apps.chatbot.errors import classify_chatbot_error
from apps.chatbot.models import ChatMessageRequest, ChatMessageResponse
from apps.chatbot.store import ChatStore
from apps.security.oidc import Identity
from database import AsyncSessionLocal
from domain.contracts.logging import logger


CHAT_STREAM_REQUESTS = Counter(
    "aiops_chatbot_stream_requests_total",
    "AIOps chatbot streaming requests",
    ["outcome"],
)
CHAT_FIRST_CHUNK_LATENCY = Histogram(
    "aiops_chatbot_first_token_latency_seconds",
    "Seconds until the first user-visible answer chunk",
)
CHAT_STREAM_INTERRUPTED = Counter(
    "aiops_chatbot_stream_interrupted_total",
    "AIOps chatbot streams interrupted before terminal delivery",
)


def _sse(event: str, payload: dict[str, Any]) -> bytes:
    encoded = json.dumps(payload, ensure_ascii=False, default=str, separators=(",", ":"))
    return f"event: {event}\ndata: {encoded}\n\n".encode("utf-8")


def _chunks(text: str, size: int = 28) -> list[str]:
    value = str(text or "")
    if not value:
        return []
    return [value[index:index + size] for index in range(0, len(value), size)]


async def _cancel_inflight(task: asyncio.Task[Any]) -> None:
    """Request cancellation and give the child coroutine a scheduling turn to clean up."""

    if task.done():
        return
    task.cancel()
    # Merely calling Task.cancel() does not run provider/MCP cleanup immediately.
    # Yield once so finally blocks can release sockets/resources before the SSE
    # generator itself exits. Never wait indefinitely on cancellation cleanup.
    await asyncio.sleep(0)
    if task.done():
        try:
            task.result()
        except asyncio.CancelledError:
            pass
        except Exception:
            # The terminal stream state is already determined by the parent;
            # consuming a late child failure prevents an unhandled-task warning.
            pass


async def _ensure_session(identity: Identity, request: ChatMessageRequest) -> ChatMessageRequest:
    if request.session_id is not None:
        return request
    async with AsyncSessionLocal() as db:
        row = await ChatStore(db).create_session(identity.subject, identity.roles)
    return request.model_copy(update={"session_id": row["session_id"]})


async def _persist_terminal_error(
    session_id: UUID | str | None,
    *,
    message: str,
    code: str,
    component: str,
    retryable: bool,
) -> None:
    if session_id is None:
        return
    try:
        async with AsyncSessionLocal() as db:
            await ChatStore(db).add_message(
                session_id,
                "assistant",
                message,
                {
                    "kind": "error",
                    "error_code": code,
                    "component": component,
                    "retryable": retryable,
                },
            )
    except Exception as exc:
        logger.warning(
            "chatbot_terminal_error_persistence_failed",
            error_type=type(exc).__name__,
            session_id=str(session_id),
        )


async def _persist_interruption(session_id: UUID | str | None) -> None:
    try:
        await asyncio.shield(
            _persist_terminal_error(
                session_id,
                message="پاسخ متوقف شد. در صورت نیاز دوباره تلاش کنید.",
                code="REQUEST_INTERRUPTED",
                component="chat",
                retryable=True,
            )
        )
    except Exception:
        # Stream shutdown must not be converted into a second user-visible
        # failure if the durability write itself cannot complete.
        pass


async def _event_stream(
    service,
    identity: Identity,
    request: ChatMessageRequest,
    *,
    request_id: str | None,
) -> AsyncIterator[bytes]:
    started = time.perf_counter()
    session_id = request.session_id
    task = asyncio.create_task(service.message(identity, request))
    first_chunk_observed = False
    heartbeat = 0
    result_ready = False

    try:
        # Keep the initial frames inside the same protected lifetime as provider
        # work. A client can disconnect immediately after either yield, and that
        # early close must still cancel in-flight work and record interruption.
        yield _sse("session", {"session_id": str(session_id), "request_id": request_id})
        yield _sse(
            "status",
            {"phase": "analysis", "message": "در حال تحلیل درخواست و بررسی ابزارهای مجاز…"},
        )

        while not task.done():
            try:
                await asyncio.wait_for(asyncio.shield(task), timeout=3.0)
            except asyncio.TimeoutError:
                heartbeat += 1
                elapsed = round(time.perf_counter() - started, 1)
                message = "در حال پردازش…" if heartbeat < 3 else "هنوز در حال پردازش؛ ارتباط برقرار است…"
                yield _sse(
                    "heartbeat",
                    {"phase": "working", "message": message, "elapsed_seconds": elapsed},
                )

        result: ChatMessageResponse = task.result()
        result_ready = True
        if result.tool or result.source:
            yield _sse(
                "status",
                {
                    "phase": "tool-complete",
                    "message": "داده عملیاتی دریافت شد؛ در حال آماده‌سازی پاسخ…",
                    "tool": result.tool,
                    "source": result.source,
                },
            )
        else:
            yield _sse("status", {"phase": "answer", "message": "پاسخ آماده شد…"})

        metadata = result.model_dump(mode="json")
        metadata["message"] = ""
        yield _sse("answer_start", metadata)

        # The currently verified Dotin adapter is request/response-only. SSE
        # provides immediate heartbeats while it works and then bounded deltas
        # for the typewriter presentation. The same delta contract can forward
        # native provider chunks after the real gateway stream is accepted.
        for chunk in _chunks(result.message):
            if not first_chunk_observed:
                CHAT_FIRST_CHUNK_LATENCY.observe(max(0.0, time.perf_counter() - started))
                first_chunk_observed = True
            yield _sse("delta", {"text": chunk})
            await asyncio.sleep(0.012)

        complete = result.model_dump(mode="json")
        complete["request_id"] = request_id
        yield _sse("complete", complete)
        CHAT_STREAM_REQUESTS.labels(outcome="completed").inc()
    except asyncio.CancelledError:
        CHAT_STREAM_INTERRUPTED.inc()
        CHAT_STREAM_REQUESTS.labels(outcome="interrupted").inc()
        await _cancel_inflight(task)
        if not result_ready:
            await _persist_interruption(session_id)
        raise
    except GeneratorExit:
        # Async-generator close is how an early HTTP disconnect can surface when
        # the generator is suspended on a yield. Treat it as an interruption too.
        CHAT_STREAM_INTERRUPTED.inc()
        CHAT_STREAM_REQUESTS.labels(outcome="interrupted").inc()
        await _cancel_inflight(task)
        if not result_ready:
            await _persist_interruption(session_id)
        raise
    except Exception as exc:
        descriptor = classify_chatbot_error(exc)
        CHAT_STREAM_REQUESTS.labels(outcome="failed").inc()
        await _persist_terminal_error(
            session_id,
            message=descriptor.message,
            code=descriptor.code,
            component=descriptor.component,
            retryable=descriptor.retryable,
        )
        logger.warning(
            "chatbot_stream_terminal_error",
            error_type=type(exc).__name__,
            error_code=descriptor.code,
            component=descriptor.component,
            session_id=str(session_id),
            request_id=request_id,
        )
        yield _sse("error", descriptor.public_payload(request_id=request_id))
    finally:
        await _cancel_inflight(task)


async def chatbot_streaming_response(
    service,
    identity: Identity,
    request: ChatMessageRequest,
    *,
    request_id: str | None = None,
) -> StreamingResponse:
    prepared = await _ensure_session(identity, request)
    response = StreamingResponse(
        _event_stream(service, identity, prepared, request_id=request_id),
        media_type="text/event-stream",
    )
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["X-Accel-Buffering"] = "no"
    response.headers["Connection"] = "keep-alive"
    return response
