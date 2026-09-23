from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any

from domain.contracts.redaction import redact

IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
PATH_RE = re.compile(r"(?<![\w.])/(?:[A-Za-z0-9._-]+/?)+")
PERSIAN_RE = re.compile(r"[\u0600-\u06ff]")

KNOWLEDGE = (" چیست", "چیست", "یعنی چی", "what is", "explain", "تعریف")
DIAGNOSTIC = ("چرا", "علت", "ریشه", "root cause", "why ", "بالا نمیاد", "بالا نمی آید", "کند شده", "slow", "failure")
ACTION = ("restart", "start ", "reload", "rollback", "scale ", "ریستارت", "استارت", "بالا بیار", "اجرا کن", "اعمال کن")
OPERATIONAL = (
    "وضعیت", "الان", "current", "status", "cpu", "memory", "ram", "swap", "disk", "دیسک",
    "فضا", "خالی", "service", "سرویس", "nginx", "haproxy", "port", "پورت", "log", "لاگ",
    "alert", "zabbix", "prometheus", "elastic", "kubernetes", "pod", "deployment", "latency", "metric",
)


@dataclass(frozen=True, slots=True)
class RequestPolicy:
    kind: str
    requires_live_evidence: bool
    diagnostic: bool = False
    mutating: bool = False
    required_capabilities: tuple[str, ...] = ()


@dataclass(slots=True)
class OperationalContext:
    target: str | None = None
    service: str | None = None
    namespace: str | None = None
    path: str | None = None
    last_tool: str | None = None

    def compact(self) -> dict[str, Any]:
        return {k: v for k, v in asdict(self).items() if v not in (None, "")}


@dataclass(slots=True)
class EvidenceRecord:
    evidence_id: str
    source: str
    tool: str
    action: str
    target: str
    observed_at: datetime
    status: str
    data: Any = None
    error_type: str | None = None

    def public(self, data: bool = False) -> dict[str, Any]:
        out = {
            "evidence_id": self.evidence_id, "source": self.source, "tool": self.tool,
            "action": self.action, "target": self.target, "status": self.status,
            "observed_at": self.observed_at.astimezone(timezone.utc).isoformat(),
        }
        if self.error_type:
            out["error_type"] = self.error_type
        if data:
            out["data"] = redact(self.data)
        return out


@dataclass(slots=True)
class RuleValidation:
    valid: bool
    needs_replan: bool
    evidence_sufficient: bool
    confidence: float
    coverage: float
    missing_evidence: list[str] = field(default_factory=list)
    reason: str = ""


@dataclass(slots=True)
class JudgeDecision:
    valid: bool = False
    question_answered: bool = False
    evidence_sufficient: bool = False
    claims_grounded: bool = False
    hallucination_risk: str = "unknown"
    tool_usage_complete: bool = False
    missing_capabilities: list[str] = field(default_factory=list)
    missing_evidence: list[str] = field(default_factory=list)
    contradictions: list[str] = field(default_factory=list)
    unsupported_claims: list[str] = field(default_factory=list)
    needs_replan: bool = False
    needs_user_clarification: bool = False
    rewrite_required: bool = False
    confidence: float = 0.0
    reason: str = ""

    @classmethod
    def parse(cls, text: str) -> "JudgeDecision":
        raw = str(text or "").strip()
        if raw.startswith("```"):
            raw = re.sub(r"^```(?:json)?\s*", "", raw, flags=re.I)
            raw = re.sub(r"\s*```$", "", raw)
        value = json.loads(raw)
        if not isinstance(value, dict):
            raise ValueError("chatbot_judge_response_not_object")
        lists = ("missing_capabilities", "missing_evidence", "contradictions", "unsupported_claims")
        kwargs: dict[str, Any] = {}
        for key in lists:
            item = value.get(key)
            kwargs[key] = [str(x)[:500] for x in item[:20]] if isinstance(item, list) else []
        try:
            confidence = min(max(float(value.get("confidence", 0.0)), 0.0), 1.0)
        except (TypeError, ValueError):
            confidence = 0.0
        return cls(
            valid=bool(value.get("valid")), question_answered=bool(value.get("question_answered")),
            evidence_sufficient=bool(value.get("evidence_sufficient")), claims_grounded=bool(value.get("claims_grounded")),
            hallucination_risk=str(value.get("hallucination_risk") or "unknown")[:32],
            tool_usage_complete=bool(value.get("tool_usage_complete")),
            needs_replan=bool(value.get("needs_replan")),
            needs_user_clarification=bool(value.get("needs_user_clarification")),
            rewrite_required=bool(value.get("rewrite_required")), confidence=confidence,
            reason=str(value.get("reason") or "")[:2000], **kwargs,
        )


def _has(text: str, markers: tuple[str, ...]) -> bool:
    folded = text.casefold()
    return any(x.casefold() in folded for x in markers)


def required_capabilities(message: str, diagnostic: bool = False) -> tuple[str, ...]:
    text = message.casefold()
    caps: list[str] = []
    def add(value: str) -> None:
        if value not in caps:
            caps.append(value)
    if any(x in text for x in ("cpu", "memory", "ram", "swap", "load", "متریک")):
        add("vm.metrics.read")
    if any(x in text for x in ("disk", "filesystem", "mount", "فضا", "دیسک", "/app", "/var", "/opt")):
        add("vm.disk.read")
    if any(x in text for x in ("service", "سرویس", "nginx", "haproxy", "systemd", "بالاست")):
        add("vm.service.status.read")
    if any(x in text for x in ("log", "لاگ", "journal")):
        add("logs.read")
    if any(x in text for x in ("zabbix", "alert", "هشدار")):
        add("zabbix.problems.read")
    if any(x in text for x in ("prometheus", "metric", "latency", "error rate")):
        add("prometheus.metrics.read")
    if any(x in text for x in ("elastic", "elasticsearch", "kibana")):
        add("elasticsearch.logs.read")
    if any(x in text for x in ("kubernetes", "k8s", "pod", "deployment", "namespace")):
        add("kubernetes.read")
    if _has(text, ACTION):
        if any(x in text for x in ("kubernetes", "k8s", "pod", "deployment", "workload")):
            add("kubernetes.action")
        elif any(x in text for x in ("service", "سرویس", "nginx", "haproxy")):
            add("vm.service.action")
    if diagnostic and ("vm.service.status.read" in caps or any(x in text for x in ("nginx", "haproxy", "سرویس"))):
        add("vm.service.status.read")
        add("vm.service.logs.read")
        add("vm.service.config.read")
    return tuple(caps)


def infer_request_policy(message: str) -> RequestPolicy:
    text = str(message or "").strip()
    diagnostic = _has(text, DIAGNOSTIC)
    knowledge = _has(text, KNOWLEDGE)
    action = _has(text, ACTION)
    operational = _has(text, OPERATIONAL) or bool(IP_RE.search(text))
    if action:
        return RequestPolicy("execution_request", True, False, True, required_capabilities(text))
    if knowledge and not diagnostic and not IP_RE.search(text):
        return RequestPolicy("knowledge", False)
    if diagnostic:
        return RequestPolicy("diagnostic", True, True, False, required_capabilities(text, True))
    if operational:
        return RequestPolicy("operational", True, False, False, required_capabilities(text))
    return RequestPolicy("information", False)


def resolve_context(rows: list[dict[str, Any]]) -> OperationalContext:
    context = OperationalContext()
    for row in reversed(rows):
        meta = row.get("metadata") if isinstance(row.get("metadata"), dict) else {}
        params = meta.get("parameters") if isinstance(meta.get("parameters"), dict) else {}
        context.target = context.target or (str(meta["target"]) if meta.get("target") else None)
        service = meta.get("service") or params.get("service")
        context.service = context.service or (str(service) if service else None)
        namespace = meta.get("namespace") or params.get("namespace")
        context.namespace = context.namespace or (str(namespace) if namespace else None)
        context.last_tool = context.last_tool or (str(meta["tool"]) if meta.get("tool") else None)
        content = str(row.get("content") or "")
        if context.target is None:
            ips = IP_RE.findall(content)
            context.target = ips[-1] if ips else None
        if context.path is None:
            paths = PATH_RE.findall(content)
            context.path = paths[-1] if paths else None
    return context


def context_instruction(context: OperationalContext) -> str:
    if not context.compact():
        return ""
    return (
        "Backend-resolved conversation referents; reuse only when the current turn omits them and never "
        "treat them as live health evidence: " + json.dumps(redact(context.compact()), ensure_ascii=False)
    )


def evidence_success(intent: Any, payload: dict[str, Any], number: int) -> EvidenceRecord:
    return EvidenceRecord(
        f"chat-evidence-{number}", str(payload.get("source") or "governed_tool"),
        str(intent.semantic_name), str(intent.action), str(intent.target),
        datetime.now(timezone.utc), "success", redact(payload.get("result")),
    )


def evidence_failure(intent: Any, exc: BaseException, number: int) -> EvidenceRecord:
    return EvidenceRecord(
        f"chat-evidence-{number}", str(intent.tool_name), str(intent.semantic_name),
        str(intent.action), str(intent.target), datetime.now(timezone.utc), "failed",
        error_type=type(exc).__name__,
    )


def validate_rules(
    policy: RequestPolicy, evidence: list[EvidenceRecord], draft: str, *,
    max_age_seconds: int, min_confidence: float,
) -> RuleValidation:
    if not str(draft or "").strip():
        return RuleValidation(False, policy.requires_live_evidence, False, 0.0, 0.0, ["empty answer"], "empty_draft")
    if not policy.requires_live_evidence:
        return RuleValidation(True, False, True, 1.0, 1.0, reason="non_live_request")
    now = datetime.now(timezone.utc)
    successful = [x for x in evidence if x.status == "success"]
    fresh = [x for x in successful if (now - x.observed_at).total_seconds() <= max_age_seconds]
    actions = {x.action for x in fresh}
    missing: list[str] = []
    if not fresh:
        missing.append("no fresh successful live evidence")
    if policy.diagnostic and len(actions) < 2:
        missing.append("diagnostic answer requires at least two corroborating live checks")
    required_checks = 2 if policy.diagnostic else 1
    coverage = min(1.0, len(actions) / required_checks) if fresh else 0.0
    if fresh:
        freshness_scores = [
            max(0.0, 1.0 - ((now - item.observed_at).total_seconds() / max(max_age_seconds, 1)))
            for item in fresh
        ]
        freshness = sum(freshness_scores) / len(freshness_scores)
    else:
        freshness = 0.0
    reliability = len(successful) / max(len(evidence), 1)
    corroboration = 1.0 if (not policy.diagnostic or len(actions) >= 2) else 0.0
    confidence = min(
        1.0,
        (0.45 * coverage)
        + (0.20 * freshness)
        + (0.20 * corroboration)
        + (0.15 * reliability),
    )
    valid = not missing and confidence >= min_confidence
    return RuleValidation(valid, not valid, valid, confidence, coverage, missing, "rules_passed" if valid else "insufficient_evidence")


JUDGE_SYSTEM_PROMPT = """You validate a production AIOps copilot answer. Evaluate only; do not answer the user.
Current operational facts require successful fresh live Evidence. Historical memory is context, not current proof.
Reject unsupported facts, contradictions, stale/failed evidence, and manual-how-to answers when a connected tool
should perform the check. Diagnostic conclusions need corroborating checks, not only service status.
If another available read tool is needed set needs_replan=true. If the required capability is unavailable, list it
under missing_capabilities. Return JSON only with: valid, question_answered, evidence_sufficient, claims_grounded,
hallucination_risk, tool_usage_complete, missing_capabilities, missing_evidence, contradictions, unsupported_claims,
needs_replan, needs_user_clarification, rewrite_required, confidence, reason."""


def judge_input(question: str, policy: RequestPolicy, context: OperationalContext,
                evidence: list[EvidenceRecord], draft: str, rule: RuleValidation,
                historical_context: Any = None) -> str:
    payload = {
        "question": question[:4000], "policy": asdict(policy), "context": context.compact(),
        "evidence": [x.public(data=True) for x in evidence],
        "historical_context_not_live_evidence": redact(historical_context or []),
        "draft": draft[:8000], "rule": asdict(rule),
    }
    text = json.dumps(redact(payload), ensure_ascii=False, default=str)
    return text[:24000]


def judge_allows_display(judge: JudgeDecision) -> bool:
    return bool(
        judge.valid
        and judge.question_answered
        and judge.evidence_sufficient
        and judge.claims_grounded
        and not judge.unsupported_claims
        and not judge.contradictions
    )


def combined_confidence(rule: RuleValidation, judge: JudgeDecision | None) -> float:
    return min(
        1.0,
        max(
            0.0,
            rule.confidence * (0.9 if judge is None else 0.6)
            + (0.0 if judge is None else judge.confidence * 0.4),
        ),
    )


def missing_capability_message(message: str, policy: RequestPolicy) -> str:
    caps = ", ".join(policy.required_capabilities) or "live operational evidence"
    if PERSIAN_RE.search(message):
        return (
            f"برای پاسخ به این سؤال باید وضعیت واقعی محیط از ابزار عملیاتی بررسی شود، اما شواهد کافی برای «{caps}» "
            "در دسترس نیست. بنابراین وضعیت فعلی را حدس نمی‌زنم. با اتصال قابلیت/MCP مناسب، همین سؤال قابل بررسی زنده است."
        )
    return (
        f"This requires live operational evidence for {caps}, but sufficient evidence is not available. "
        "I will not guess the current state; connect the required MCP/capability to answer it live."
    )


def guarded_failure_message(message: str, evidence: list[EvidenceRecord], reason: str) -> str:
    if PERSIAN_RE.search(message):
        return (
            f"مرحله صحت‌سنجی نتوانست یک پاسخ عملیاتی قابل اتکا را تأیید کند ({reason}). "
            "به‌جای نمایش نتیجه حدسی، پاسخ متوقف شد؛ شواهد جمع‌آوری‌شده همچنان قابل بررسی است."
        )
    return (
        f"Final validation could not confirm a reliable operational answer ({reason}). "
        "The unsupported conclusion was withheld; collected evidence remains available."
    )
