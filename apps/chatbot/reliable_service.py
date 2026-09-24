from __future__ import annotations

import asyncio
import json
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
CHAT_DETERMINISTIC_READ_FALLBACKS = Counter(
    "aiops_chatbot_deterministic_read_fallback_total",
    "Clear live VM reads resolved deterministically after a model omitted the governed tool call",
    ["tool"],
)

_PERSIAN_RE = re.compile(r"[\u0600-\u06ff]")
_TERMINAL_PUNCTUATION = tuple(".!?؟…؛:)]}»\"'")
_NONTERMINAL_TOOL_PREAMBLE_PATTERNS = (
    re.compile(r"(?:بررسی|چک|استعلام)\s*(?:می\s*کنم|خواهم\s*کرد)", re.IGNORECASE),
    re.compile(r"(?:ابتدا|اول).*(?:بررسی|چک).*(?:سپس|بعد)", re.IGNORECASE | re.DOTALL),
    re.compile(r"\b(?:i(?:'ll| will)|let me)\s+(?:check|inspect|look up|verify|query|retrieve)\b", re.IGNORECASE),
    re.compile(r"\b(?:first|initially)\b.*\b(?:check|inspect|verify|query)\b.*\b(?:then|after)\b", re.IGNORECASE | re.DOTALL),
)


def _looks_like_nonterminal_tool_preamble(response: LLMResponse, *, tools_available: bool) -> bool:
    """Detect model narration that promises a governed read instead of selecting a tool."""

    if not tools_available or response.tool_calls:
        return False
    text = str(response.content or "").strip()
    if not text:
        return False
    normalized = text.replace("\u200c", " ").replace("\u200f", " ")
    return any(pattern.search(normalized) for pattern in _NONTERMINAL_TOOL_PREAMBLE_PATTERNS)


_LIVE_OPERATIONAL_QUERY_RE = re.compile(
    r"(?:"
    r"وضعیت|وضعیته|چقدره|چنده|مصرف|فعال|غیرفعال|خاموش|روشن|"
    r"لاگ|لاگ‌ها|متریک|cpu|memory|ram|"
    r"\bstatus\b|\bhealth\b|\bmetrics?\b|\blogs?\b|\bpods?\b|"
    r"\brunning\b|\bactive\b|\binactive\b"
    r")",
    re.IGNORECASE,
)
_FOLLOWUP_LOCATOR_RE = re.compile(
    r"(?:\b\d{1,3}(?:\.\d{1,3}){1,3}\b|چی(?:ه)?\s*$|what about|how about)",
    re.IGNORECASE,
)
_LIVE_INSPECTION_RE = re.compile(
    r"(?:بررسی(?:\s|\u200c)*کن|چک(?:\s|\u200c)*کن|ببین|استعلام(?:\s|\u200c)*کن|"
    r"\bcheck\b|\binspect\b|\bverify\b|\blook\s+up\b|\bquery\b)",
    re.IGNORECASE,
)
_OPERATIONAL_LOCATOR_RE = re.compile(
    r"(?:\b\d{1,3}(?:\.\d{1,3}){1,3}\b|"
    r"سرور|هاست|سرویس|پاد|نام(?:\s|\u200c)*اسپیس|دیسک|شبکه|پورت|پروسس|پردازش|"
    r"\bserver\b|\bhost\b|\bvm\b|\bservice\b|\bpod\b|\bnamespace\b|"
    r"\bkubernetes\b|\bk8s\b|\bzabbix\b|\bdisk\b|\bnetwork\b|\bport\b|\bprocess\b)",
    re.IGNORECASE,
)
_ASCII_RESOURCE_TOKEN_RE = re.compile(r"\b[a-z][a-z0-9_.-]{2,}\b", re.IGNORECASE)
_FULL_IPV4_RE = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
_IP_SUFFIX_RE = re.compile(r"(?<![\d.])(\d{1,3})\.(\d{1,3})(?![\d.])")
_SERVICE_TOKEN_RE = re.compile(r"\b[a-z][a-z0-9@_.:-]{1,63}\b", re.IGNORECASE)
_SERVICE_STOPWORDS = {
    "active", "check", "cpu", "disk", "health", "host", "inactive", "inspect",
    "k8s", "kubernetes", "load", "log", "logs", "memory", "metrics", "network",
    "pod", "pods", "query", "ram", "running", "server", "service", "status",
    "swap", "verify", "vm", "zabbix",
}


def _valid_ipv4(value: str) -> bool:
    parts = value.split(".")
    return len(parts) == 4 and all(part.isdigit() and 0 <= int(part) <= 255 for part in parts)


def _user_turns(messages: List[Dict[str, str]]) -> list[str]:
    return [
        str(item.get("content") or "").strip()
        for item in messages
        if str(item.get("role") or "") == "user" and str(item.get("content") or "").strip()
    ]


def _service_candidates(text: str) -> list[str]:
    candidates: list[str] = []
    for token in _SERVICE_TOKEN_RE.findall(text):
        value = token.lower()
        if value in _SERVICE_STOPWORDS or value.isdigit():
            continue
        if value not in candidates:
            candidates.append(value)
    return candidates


def _resolve_service_from_turns(turns: list[str]) -> str | None:
    if not turns:
        return None
    current = _service_candidates(turns[-1])
    if len(current) == 1:
        return current[0]
    if len(current) > 1 or len(turns) < 2:
        return None

    # Referent carry-over is intentionally one operator turn only. This keeps
    # "6.200چی" after an nginx question deterministic, while preventing an old
    # service name from leaking across a newer generic server-status request.
    previous = _service_candidates(turns[-2])
    return previous[0] if len(previous) == 1 else None


def _resolve_vm_target_from_turns(turns: list[str]) -> str | None:
    if not turns:
        return None
    current = turns[-1]
    explicit = [value for value in _FULL_IPV4_RE.findall(current) if _valid_ipv4(value)]
    explicit = list(dict.fromkeys(explicit))
    if len(explicit) == 1:
        return explicit[0]
    if len(explicit) > 1:
        return None

    suffixes = []
    for left, right in _IP_SUFFIX_RE.findall(current):
        if 0 <= int(left) <= 255 and 0 <= int(right) <= 255:
            suffixes.append((left, right))
    suffixes = list(dict.fromkeys(suffixes))
    prior_targets: list[str] = []
    for previous in reversed(turns[:-1]):
        for value in _FULL_IPV4_RE.findall(previous):
            if _valid_ipv4(value) and value not in prior_targets:
                prior_targets.append(value)

    if len(suffixes) == 1:
        suffix = ".".join(suffixes[0])
        matches = [value for value in prior_targets if value.endswith("." + suffix)]
        if len(matches) == 1:
            return matches[0]
        if matches:
            return None

        # Operator shorthand such as "6.200" means "same recent network
        # prefix, replace the final two octets". Reconstruct it only when the
        # recent explicit VM targets agree on one two-octet prefix.
        prefixes = {
            ".".join(value.split(".")[:2])
            for value in prior_targets
        }
        if len(prefixes) == 1:
            candidate = next(iter(prefixes)) + "." + suffix
            return candidate if _valid_ipv4(candidate) else None
        return None

    return prior_targets[0] if prior_targets else None


def _available_tool_names(tools: Any) -> set[str]:
    names: set[str] = set()
    if not isinstance(tools, list):
        return names
    for item in tools:
        if not isinstance(item, dict):
            continue
        function = item.get("function")
        if isinstance(function, dict):
            name = str(function.get("name") or "").strip()
            if name:
                names.add(name)
    return names


def _deterministic_vm_service_read_call(
    messages: List[Dict[str, str]],
    *,
    tools: Any,
) -> dict[str, Any] | None:
    """Build only an unambiguous governed VM service read; never infer a write."""

    turns = _user_turns(messages)
    if not turns:
        return None
    current = turns[-1].replace("\u200c", " ")
    if not (
        _LIVE_INSPECTION_RE.search(current)
        or _LIVE_OPERATIONAL_QUERY_RE.search(current)
        or _FOLLOWUP_LOCATOR_RE.search(current)
    ):
        return None

    target = _resolve_vm_target_from_turns(turns)
    service = _resolve_service_from_turns(turns)
    if not target or not service:
        return None

    available = _available_tool_names(tools)
    wants_logs = bool(re.search(r"(?:لاگ|log|logs)", current, re.IGNORECASE))
    tool_name = "vm_service_logs" if wants_logs else "vm_service_status"
    if tool_name not in available:
        return None

    arguments: dict[str, Any] = {"target": target, "service": service}
    return {
        "id": "deterministic-vm-service-read",
        "type": "function",
        "function": {
            "name": tool_name,
            "arguments": json.dumps(arguments, ensure_ascii=False, separators=(",", ":")),
        },
    }


def _requires_live_operational_tool(messages: List[Dict[str, str]], *, tools_available: bool) -> bool:
    """Fail closed for clear live-read requests before any governed tool has run."""

    if not tools_available:
        return False
    operator_turns = [
        str(item.get("content") or "").strip()
        for item in messages
        if str(item.get("role") or "") == "user" and str(item.get("content") or "").strip()
    ]
    if not operator_turns:
        return False
    current = operator_turns[-1]
    normalized_current = current.replace("\u200c", " ")
    prior_turns = operator_turns[-7:-1]

    if _LIVE_OPERATIONAL_QUERY_RE.search(normalized_current):
        return True

    if _LIVE_INSPECTION_RE.search(normalized_current):
        if _OPERATIONAL_LOCATOR_RE.search(normalized_current):
            return True
        # Conversational service checks such as "haproxy بررسی کن" may inherit
        # the target from recent operator context. Require a resource-looking
        # token in the current turn and an operational locator in history.
        if _ASCII_RESOURCE_TOKEN_RE.search(normalized_current) and any(
            _OPERATIONAL_LOCATOR_RE.search(previous.replace("\u200c", " "))
            for previous in prior_turns
        ):
            return True

    if len(normalized_current) <= 80 and _FOLLOWUP_LOCATOR_RE.search(normalized_current):
        return any(
            _LIVE_OPERATIONAL_QUERY_RE.search(previous.replace("\u200c", " "))
            or (
                _LIVE_INSPECTION_RE.search(previous.replace("\u200c", " "))
                and _OPERATIONAL_LOCATOR_RE.search(previous.replace("\u200c", " "))
            )
            for previous in prior_turns
        )
    return False


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


def _safe_policy_denial(exc: BaseException | None) -> str | None:
    if exc is None:
        return None
    value = str(exc)
    if value in {"vm_target_not_allowed", "vm_service_not_allowed"}:
        return value
    return None


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
        requires_live_tool = _requires_live_operational_tool(
            messages,
            tools_available=tools_available,
        )
        missing_required_live_tool = requires_live_tool and not response.tool_calls
        if stage != "chatbot_intent" or not (
            incomplete or nonterminal_tool_preamble or missing_required_live_tool
        ):
            return response

        if missing_required_live_tool:
            deterministic_call = _deterministic_vm_service_read_call(
                messages,
                tools=kwargs.get("tools"),
            )
            if deterministic_call is not None:
                tool_name = str((deterministic_call.get("function") or {}).get("name") or "unknown")
                CHAT_DETERMINISTIC_READ_FALLBACKS.labels(tool=tool_name).inc()
                return LLMResponse(
                    content="",
                    model=response.model,
                    usage=response.usage,
                    tool_calls=[deterministic_call],
                    finish_reason="tool_calls",
                )

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
        repair_kwargs = dict(kwargs)
        if requires_live_tool and tools_available:
            # The first model turn already proved that a live governed read is
            # required. Do not allow the bounded repair turn to narrate or
            # fabricate another direct answer; require a structured tool call.
            repair_kwargs["tool_choice"] = "required"
        try:
            repaired = await self.delegate.generate_with_messages(
                repair_messages,
                temperature=temperature,
                max_tokens=max(1, int(max_tokens)) * 2,
                **repair_kwargs,
            )
        except Exception as exc:
            if _is_timeout_error(exc):
                CHAT_LLM_TIMEOUTS.inc()
            raise
        if (
            _looks_obviously_incomplete(repaired)
            or _looks_like_nonterminal_tool_preamble(
                repaired,
                tools_available=tools_available,
            )
            or (requires_live_tool and not repaired.tool_calls)
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
                policy_denial = _safe_policy_denial(cause)
                if policy_denial == "vm_target_not_allowed":
                    raise HTTPException(status_code=403, detail=f"chatbot_target_not_allowed:{tool}") from cause
                if policy_denial == "vm_service_not_allowed":
                    raise HTTPException(status_code=403, detail=f"chatbot_service_not_allowed:{tool}") from cause
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
