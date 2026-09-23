from __future__ import annotations

import asyncio
import re
import time
from typing import Any, Dict, List, Optional

from fastapi import HTTPException
from prometheus_client import Counter, Histogram

from apps.chatbot.governance import (
    CHAT_MISSING_CAPABILITIES,
    ChatGovernanceConfig,
    build_evidence,
    cognia_write_unavailable_message,
    grounded_fallback,
    llm_validate,
    missing_capability_message,
    most_recent_user_message,
    requires_cognia_write,
    requires_live_evidence,
)
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
        if stage != "chatbot_intent":
            return response

        user_message = most_recent_user_message(messages)
        cfg = ChatGovernanceConfig.from_env()
        current = response
        repair_messages = list(messages)
        attempts = 0

        while True:
            incomplete = _looks_obviously_incomplete(current)
            evidence_required = requires_live_evidence(user_message) and not current.tool_calls
            cognia_write_required = requires_cognia_write(user_message) and not current.tool_calls
            if not incomplete and not evidence_required and not cognia_write_required:
                return current

            max_attempts = (
                1
                if incomplete and not evidence_required and not cognia_write_required
                else cfg.max_replan_attempts
            )
            if attempts >= max_attempts:
                break

            attempts += 1
            CHAT_INCOMPLETE_RESPONSES.inc()
            if cognia_write_required:
                repair_instruction = (
                    "REPLAN REQUIRED: the operator explicitly requested a Cognia knowledge write. "
                    "Do not merely acknowledge the request. Select exactly one provided Cognia write tool: "
                    "cognia_publish_incident_knowledge when the operator wants a verified incident/solution "
                    "published from durable AIOps data; cognia_register_knowledge for new supplied knowledge; "
                    "or cognia_create_revision only when an existing knowledge id is explicitly available. "
                    "Do not invent scope, KB authority, incident verification, or an existing knowledge id."
                )
            elif evidence_required:
                repair_instruction = (
                    "REPLAN REQUIRED: this is a live operational question. Do not answer from model memory "
                    "or infer the current state. Select the best matching provided read-only tool(s) using "
                    "the established conversation target when unambiguous. For a diagnostic 'why' question, "
                    "collect enough independent evidence to support the cause rather than stopping at a "
                    "single status check. If no provided tool can establish the requested fact, return a "
                    "short explicit statement that the live capability is unavailable; do not guess."
                )
            else:
                repair_instruction = (
                    "RETRY REQUIRED: the previous response was incomplete. Return one fresh, complete, "
                    "concise answer, or select the correct provided tool when live operational data is "
                    "required. Do not continue the partial prefix."
                )
            repair_messages = list(repair_messages)
            repair_messages.append({"role": "user", "content": repair_instruction})
            try:
                current = await self.delegate.generate_with_messages(
                    repair_messages,
                    temperature=temperature,
                    max_tokens=max(1, int(max_tokens)) * 2,
                    **kwargs,
                )
            except Exception as exc:
                if _is_timeout_error(exc):
                    CHAT_LLM_TIMEOUTS.inc()
                raise

        if _looks_obviously_incomplete(current):
            CHAT_INCOMPLETE_RESPONSES.inc()
            raise ValueError("chatbot_llm_incomplete_response")
        if requires_cognia_write(user_message) and not current.tool_calls:
            CHAT_MISSING_CAPABILITIES.inc()
            return LLMResponse(
                content=cognia_write_unavailable_message(user_message),
                model=current.model,
                usage=current.usage,
                tool_calls=None,
                finish_reason=current.finish_reason,
            )
        if requires_live_evidence(user_message) and not current.tool_calls:
            CHAT_MISSING_CAPABILITIES.inc()
            return LLMResponse(
                content=missing_capability_message(user_message),
                model=current.model,
                usage=current.usage,
                tool_calls=None,
                finish_reason=current.finish_reason,
            )
        return current


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
        evidence_kind = "knowledge" if str(payload.get("source") or "") == "cognia" else "live"
        evidence = [
            build_evidence(
                source=str(payload.get("source") or "governed_tool"),
                tool=intent.semantic_name,
                target=intent.target,
                data=payload.get("result"),
                evidence_kind=evidence_kind,
            )
        ]
        knowledge_context = payload.get("knowledge_context")
        if knowledge_context:
            evidence.append(
                build_evidence(
                    source="cognia",
                    tool="cognia_auto_lookup",
                    target="knowledge",
                    data=knowledge_context,
                    evidence_kind="knowledge",
                )
            )
        try:
            verdict = await llm_validate(
                llm=self._llm(),
                question=user_message,
                answer=answer,
                evidence=evidence,
                session_id=session_id,
                user_id=identity.subject,
            )
        except Exception:
            # Judge failure never promotes an unverified answer. The deterministic
            # fallback remains grounded in the already validated tool payload.
            return grounded_fallback(
                question=user_message,
                evidence=evidence,
                reason="answer validator unavailable",
            )

        if (
            not verdict.valid
            or not verdict.question_answered
            or not verdict.evidence_sufficient
            or not verdict.claims_grounded
            or verdict.unsupported_claims
            or verdict.contradictions
        ):
            return grounded_fallback(
                question=user_message,
                evidence=evidence,
                reason=verdict.reason or "response validation failed",
            )
        return answer
