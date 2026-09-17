from __future__ import annotations

import re
import time
from typing import Any, Dict, List, Optional

from prometheus_client import Counter, Histogram

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
            if "timeout" in type(exc).__name__.lower():
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
            if "timeout" in type(exc).__name__.lower():
                CHAT_LLM_TIMEOUTS.inc()
            raise

        stage = str(kwargs.get("stage") or kwargs.get("purpose") or "")
        if stage != "chatbot_intent" or not _looks_obviously_incomplete(response):
            return response

        # No governed tool has executed yet, so one bounded retry is safe.
        CHAT_INCOMPLETE_RESPONSES.inc()
        repair_messages = list(messages)
        repair_messages.append(
            {
                "role": "user",
                "content": (
                    "RETRY REQUIRED: the previous response was incomplete. Return one fresh, complete, "
                    "concise answer, or select the correct provided tool when live operational data is "
                    "required. Do not continue the partial prefix."
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
            if "timeout" in type(exc).__name__.lower():
                CHAT_LLM_TIMEOUTS.inc()
            raise
        if _looks_obviously_incomplete(repaired):
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
