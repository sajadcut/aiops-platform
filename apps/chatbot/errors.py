from __future__ import annotations

import asyncio
from dataclasses import asdict, dataclass
from typing import Any

from fastapi import HTTPException


@dataclass(frozen=True)
class ChatErrorDescriptor:
    code: str
    message: str
    component: str
    retryable: bool
    http_status: int

    def public_payload(self, *, request_id: str | None = None) -> dict[str, Any]:
        payload = asdict(self)
        if request_id:
            payload["request_id"] = str(request_id)
        return payload


_ERROR_MAP: dict[str, ChatErrorDescriptor] = {
    "chatbot_llm_timeout": ChatErrorDescriptor(
        code="LLM_TIMEOUT",
        message="درخواست به دلیل Timeout کامل نشد.",
        component="llm",
        retryable=True,
        http_status=504,
    ),
    "chatbot_llm_unavailable": ChatErrorDescriptor(
        code="LLM_UNAVAILABLE",
        message="LLM پاسخ نداد. دوباره تلاش کنید.",
        component="llm",
        retryable=True,
        http_status=503,
    ),
    "chatbot_llm_incomplete_response": ChatErrorDescriptor(
        code="LLM_INCOMPLETE_RESPONSE",
        message="LLM پاسخ کاملی برنگرداند. دوباره تلاش کنید.",
        component="llm",
        retryable=True,
        http_status=503,
    ),
    "insufficient_role": ChatErrorDescriptor(
        code="PERMISSION_DENIED",
        message="دسترسی کافی ندارید.",
        component="authorization",
        retryable=False,
        http_status=403,
    ),
    "chat_session_not_found": ChatErrorDescriptor(
        code="VALIDATION_ERROR",
        message="گفت‌وگو پیدا نشد.",
        component="chat",
        retryable=False,
        http_status=404,
    ),
}


def classify_chatbot_error(exc: BaseException) -> ChatErrorDescriptor:
    """Convert internal failures into short operator-safe terminal errors.

    Raw exception strings are intentionally not exposed. Detailed exceptions stay
    in structured server logs where normal redaction/correlation applies.
    """

    if isinstance(exc, HTTPException):
        detail = str(exc.detail or "")
        if detail in _ERROR_MAP:
            return _ERROR_MAP[detail]
        if detail.startswith("chatbot_tool_timeout:"):
            return ChatErrorDescriptor(
                code="MCP_TIMEOUT",
                message="ارتباط با MCP به دلیل Timeout کامل نشد.",
                component="mcp",
                retryable=True,
                http_status=504,
            )
        if detail.startswith("chatbot_tool_unavailable:"):
            return ChatErrorDescriptor(
                code="MCP_UNAVAILABLE",
                message="ارتباط با MCP برقرار نشد.",
                component="mcp",
                retryable=True,
                http_status=502,
            )
        if detail.startswith("chatbot_tool_failed:"):
            return ChatErrorDescriptor(
                code="MCP_TOOL_ERROR",
                message="MCP پاسخ نداد. دوباره تلاش کنید.",
                component="mcp",
                retryable=True,
                http_status=502,
            )
        if detail.startswith("chatbot_") and exc.status_code == 400:
            return ChatErrorDescriptor(
                code="VALIDATION_ERROR",
                message="درخواست قابل اجرا نیست. ورودی را بررسی کنید.",
                component="chat",
                retryable=False,
                http_status=400,
            )
        if exc.status_code in {401, 403}:
            return ChatErrorDescriptor(
                code="AUTH_ERROR" if exc.status_code == 401 else "PERMISSION_DENIED",
                message="نشست معتبر نیست. دوباره وارد شوید." if exc.status_code == 401 else "دسترسی کافی ندارید.",
                component="authorization",
                retryable=False,
                http_status=exc.status_code,
            )
        if exc.status_code == 409:
            return ChatErrorDescriptor(
                code="VALIDATION_ERROR",
                message="وضعیت درخواست تغییر کرده است. صفحه را تازه کنید.",
                component="chat",
                retryable=False,
                http_status=409,
            )

    name = type(exc).__name__.lower()
    if isinstance(exc, (asyncio.TimeoutError, TimeoutError)) or "timeout" in name:
        return ChatErrorDescriptor(
            code="LLM_TIMEOUT",
            message="درخواست به دلیل Timeout کامل نشد.",
            component="llm",
            retryable=True,
            http_status=504,
        )
    if "sql" in name or "database" in name or "asyncpg" in name:
        return ChatErrorDescriptor(
            code="DATABASE_ERROR",
            message="خطای موقت در دیتابیس.",
            component="database",
            retryable=True,
            http_status=503,
        )
    if "connect" in name or "network" in name:
        return ChatErrorDescriptor(
            code="MCP_UNAVAILABLE",
            message="ارتباط با MCP برقرار نشد.",
            component="mcp",
            retryable=True,
            http_status=502,
        )
    return ChatErrorDescriptor(
        code="INTERNAL_ERROR",
        message="خطای موقت رخ داد. دوباره تلاش کنید.",
        component="chat",
        retryable=True,
        http_status=500,
    )
