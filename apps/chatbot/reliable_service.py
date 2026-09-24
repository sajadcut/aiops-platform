from __future__ import annotations

import asyncio
import re
import time
from typing import Any, Dict, List, Optional

from fastapi import HTTPException
from prometheus_client import Counter, Histogram

from apps.chatbot.models import ChatMessageRequest, ChatMessageResponse
from apps.chatbot.service import ChatbotService
from apps.chatbot.tools import ToolIntent
from apps.security.oidc import Identity
from integrations.llm.base import LLMAdapter, LLMResponse
from integrations.llm.openai_compatible import configured_llm_adapter


CHAT_LLM_TIMEOUTS = Counter(
    "aiops_chatbot_llm_timeout_total",
    "AIOps chatbot LLM timeouts",
)
CHAT_INCOMPLETE_RESPONSES = Counter(
    "aiops_chatbot_incomplete_response_total",
    "AIOps chatbot incomplete model responses rejected before persistence",
)
CHAT_MCP_ERRORS = Counter(
    "aiops_chatbot_mcp_error_total",
    "AIOps chatbot governed tool/MCP failures",
    ["tool"],
)
CHAT_TOOL_LATENCY = Histogram(
    "aiops_chatbot_tool_call_latency_seconds",
    "AIOps chatbot governed tool latency",
    ["tool"],
)

_PERSIAN_RE = re.compile(r"[\u0600-\u06ff]")
_TERMINAL_PUNCTUATION = tuple(".!?؟…؛:)]}»\"'")
_NONTERMINAL_TOOL_PREAMBLE_PATTERNS = (
    re.compile(r"(?:بررسی|چک|استعلام)\\s*(?:می\\s*کنم|خواهم\\s*کرد)", re.IGNORECASE),
    re.compile(r"(?:ابتدا|اول).*(?:بررسی|چک).*(?:سپس|بعد)", re.IGNORECASE | re.DOTALL),
    re.compile(r"\\b(?:i(?:'ll| will)|let me)\\s+(?:check|inspect|look up|verify|query|retrieve)\\b", re.IGNORECASE),
    re.compile(r"\\b(?:first|initially)\\b.*\\b(?:check|inspect|verify|query)\\b.*\\b(?:then|after)\\b", re.IGNORECASE | re.DOTALL),
)


def _looks_like_nonterminal_tool_preamble(response: LLMResponse, *, tools_available: bool) -> bool:
    """Detect model narration that promises a governed read instead of selecting a tool."""

    if not tools_available or response.tool_calls:
        return False
    text = str(response.content or "").strip()
    if not text:
        return False
    return any(pattern.search(text) for pattern in _NONTERMINAL_TOOL_PREAMBLE_PATTERNS)


def _looks_obviously_incomplete(response: LLMResponse) -> bool:
    """Reject only strong incomplete-prefix signals for direct chatbot answers."""

    if response.tool_calls:
        return False
    text = str(response.content or "").strip()
    if not text:
        return True
    if text.count("**") % 2 or text.count("`") % 2:
        return True
    if len(text) < 72 and not text.endswith(_TERMINAL_PUNCTUATION):
        return True
    return False


def _is_timeout_error(exc: BaseException | None) -> bool:
    if exc is None:
        return False
    return isinstance(exc, (asyncio.TimeoutError, TimeoutError)) or "timeout" in type(exc).__name__.lower()


def _is_connection_error(exc: BaseException | None) -> bool:
    if exc is None:
        return False
    name = type(exc).__name__.lower()
    return isinstance(exc, ConnectionError) or "connect" in name or "network" in name


class ReliableChatLLMAdapter(LLMAdapter):
    """Chat-stage reliability wrapper around the configured LLM adapter."""

    def __init__(self, delegate: LLMAdapter):
        self.delegate = delegate

    @property
    def provider_name(self) -> str:
        return self.delegate.provider_name

    async def generate(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        temperature: float = 0.7,
        max_tokens: int = 1000,
        **kwargs: Any,
    ) -> LLMResponse:
        try:
            return await self.delegate.generate(
                prompt,
                system_prompt=system_prompt,
                temperature=temperature,
                max_tokens=max_tokens,
                **kwargs,
            )
        except Exception as exc:
            if _is_timeout_error(exc):
                CHAT_LLM_TIMEOUTS.inc()
            raise

    async def generate_with_messages(
        self,
        messages: List[Dict[str, str]],
        temperature: float = 0.7,
        max_tokens: int = 1000,
        **kwargs: Any,
    ) -> LLMResponse:
        try:
            response = await self.delegate.generate_with_messages(
                messages,
                temperature=temperature,
                max_tokens=max_tokens,
                **kwargs,
            )
        except Exception as exc:
            if _is_timeout_error(exc):
                CHAT_LLM_TIMEOUTS.inc()
            raise

        stage = str(kwargs.get("stage") or kwargs.get("purpose") or "")
        tools_available = bool(kwargs.get("tools"))
        incomplete = _looks_obviously_incomplete(response)
        nonterminal_tool_preamble = _looks_like_nonterminal_tool_preamble(
            response,
            tools_available=tools_available,
        )
        if stage != "chatbot_intent" or not (incomplete or nonterminal_tool_preamble):
            return response

        # No governed tool has executed yet, so one bounded retry is safe.
        # A model sentence such as "I'll check that now" is not a terminal
        # operational answer: with live-read tools available it must either
        # select a governed tool or provide an actually complete direct answer.
        CHAT_INCOMPLETE_RESPONSES.inc()
        repair_messages = list(messages)
        repair_messages.append(
            {
                "role": "user",
                "content": (
                    "RETRY REQUIRED: the previous response was incomplete or only narrated a future check. "
                    "Return one fresh, complete, concise answer, or select the correct provided governed tool "
                    "when live operational data is required. Do not say that you will check/inspect/query later; "
                    "select the tool now. Do not continue the previous prefix."
                ),
            }
        )
        try:
            repaired = await self.delegate.generate_with_messages(
                repair_messages,
                temperature=temperature,
                max_tokens=max(1, int(max_tokens)) * 2,
                **kwargs,
            )
        except Exception as exc:
            if _is_timeout_error(exc):
                CHAT_LLM_TIMEOUTS.inc()
            raise
        if _looks_obviously_incomplete(repaired) or _looks_like_nonterminal_tool_preamble(
            repaired,
            tools_available=tools_available,
        ):
            CHAT_INCOMPLETE_RESPONSES.inc()
            raise ValueError("chatbot_llm_incomplete_response")
        return repaired


class OperationsCopilotService(ChatbotService):
    """ChatbotService reliability/UI adapter without changing governance boundaries."""

    def __init__(self, llm: Optional[LLMAdapter] = None):
        super().__init__(llm)
        self._reliable_adapter: ReliableChatLLMAdapter | None = None

    def _llm(self) -> LLMAdapter:
        if self._reliable_adapter is None:
            delegate = self._configured_llm or configured_llm_adapter()
            self._reliable_adapter = (
                delegate if isinstance(delegate, ReliableChatLLMAdapter) else ReliableChatLLMAdapter(delegate)
            )
        return self._reliable_adapter

    async def message(self, identity: Identity, request: ChatMessageRequest) -> ChatMessageResponse:
        """Preserve safe cause categories after the base service fail-closed wrapper.

        The base service intentionally converts provider/tool exceptions into
        stable HTTP errors. This outer production adapter keeps those internals
        private while restoring the distinctions the UI needs for actionable,
        short terminal outcomes.
        """

        try:
            return await super().message(identity, request)
        except HTTPException as exc:
            detail = str(exc.detail or "")
            cause = exc.__cause__
            if detail == "chatbot_llm_unavailable":
                if isinstance(cause, ValueError) and str(cause) == "chatbot_llm_incomplete_response":
                    raise HTTPException(status_code=503, detail="chatbot_llm_incomplete_response") from cause
                if _is_timeout_error(cause):
                    raise HTTPException(status_code=504, detail="chatbot_llm_timeout") from cause
            if detail.startswith("chatbot_tool_failed:"):
                tool = detail.partition(":")[2]
                if _is_timeout_error(cause):
                    raise HTTPException(status_code=504, detail=f"chatbot_tool_timeout:{tool}") from cause
                if _is_connection_error(cause):
                    raise HTTPException(status_code=502, detail=f"chatbot_tool_unavailable:{tool}") from cause
            raise

    async def _execute_read(self, intent: ToolIntent, session_id: str) -> dict[str, Any]:
        started = time.perf_counter()
        try:
            return await super()._execute_read(intent, session_id)
        except Exception:
            CHAT_MCP_ERRORS.labels(tool=intent.semantic_name).inc()
            raise
        finally:
            CHAT_TOOL_LATENCY.labels(tool=intent.semantic_name).observe(
                max(0.0, time.perf_counter() - started)
            )

    async def _summarize(
        self,
        user_message: str,
        intent: ToolIntent,
        payload: dict[str, Any],
        identity: Identity,
        session_id: str,
        recent_operator_context: str = "",
    ) -> str:
        answer = await super()._summarize(
            user_message,
            intent,
            payload,
            identity,
            session_id,
            recent_operator_context,
        )
        # The base service falls back to bounded raw JSON if summary generation
        # fails. Keep the structured data in response.data but make the primary
        # operator message short and readable.
        fallback_prefix = f"{intent.semantic_name} completed via "
        if answer.startswith(fallback_prefix) and " Result: " in answer:
            source = str(payload.get("source") or "governed tool")
            recent = f"{recent_operator_context}\n{user_message}"
            if _PERSIAN_RE.search(recent):
                return (
                    f"داده عملیاتی با موفقیت از {source} دریافت شد، اما LLM نتوانست خلاصه "
                    "قابل‌اعتماد تولید کند. جزئیات منبع را در بخش «جزئیات» ببینید."
                )
            return (
                f"Operational data was received successfully from {source}, but the LLM could not "
                "produce a reliable summary. Open Details to inspect the governed source data."
            )
        return answer
