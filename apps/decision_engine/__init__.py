from __future__ import annotations

from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

from domain.contracts.logging import logger


class RiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class DecisionAction(str, Enum):
    AUTO_EXECUTE = "auto_execute"
    REQUIRE_APPROVAL = "require_approval"
    REJECT = "reject"
    ESCALATE = "escalate"


class DecisionResult(BaseModel):
    action: DecisionAction
    risk_level: RiskLevel
    reason: str
    requires_approval: bool
    suggested_approver: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)


class DecisionEngine:
    """Deterministic policy gate for an RCA plan and the concrete action request.

    The free-form LLM/RCA plan is never the sole source of execution risk. When
    an execution request exists, its action and the registered tool contract are
    evaluated too, and the highest risk wins.
    """

    HIGH_RISK_KEYWORDS = [
        "delete", "drop", "remove", "shutdown", "reboot", "rollback",
        "restore", "reset", "purge", "kill", "terminate", "drain",
        "cordon", "rotate", "revoke", "disable",
    ]
    MEDIUM_RISK_KEYWORDS = [
        "restart", "redeploy", "scale", "update", "change", "modify",
        "config", "reload", "start", "stop", "enable", "patch", "apply",
    ]
    LOW_RISK_KEYWORDS = [
        "check", "investigate", "review", "monitor", "observe", "log",
        "query", "describe", "list", "status", "collect", "snapshot",
    ]
    _RISK_ORDER = {
        RiskLevel.LOW: 1,
        RiskLevel.MEDIUM: 2,
        RiskLevel.HIGH: 3,
        RiskLevel.CRITICAL: 4,
    }

    @classmethod
    def evaluate_plan(
        cls,
        plan: str,
        findings: List[Dict[str, Any]],
        *,
        execution_request: Optional[Dict[str, Any]] = None,
        tool_risk_level: Optional[str] = None,
        tool_requires_approval: bool = False,
        tool_exists: bool = True,
    ) -> DecisionResult:
        logger.info("Decision Engine: evaluating plan and execution binding")
        plan_risk = cls._assess_risk(plan)
        request = execution_request or {}
        request_action = str(request.get("action") or "")
        request_risk = cls._assess_risk(request_action) if request_action else RiskLevel.LOW
        tool_risk = cls._normalize_risk(tool_risk_level)

        effective_risk = cls._max_risk(plan_risk, request_risk, tool_risk)
        avg_confidence = cls._calculate_avg_confidence(findings)
        binding_complete = bool(
            request.get("tool_name") and request.get("action") and request.get("target")
        ) if request else False

        if request and not binding_complete:
            decision = DecisionAction.REJECT
            reason = "Execution request is incomplete and cannot be policy-evaluated safely."
        elif request and not tool_exists:
            decision = DecisionAction.REJECT
            reason = "Requested execution tool is not registered."
        else:
            decision, reason = cls._make_decision(
                effective_risk,
                avg_confidence,
                force_approval=bool(request and tool_requires_approval),
            )

        logger.info(
            "Decision: %s | risk=%s | plan_risk=%s | request_risk=%s | tool_risk=%s | reason=%s",
            decision.value,
            effective_risk.value,
            plan_risk.value,
            request_risk.value,
            tool_risk.value,
            reason,
        )
        return DecisionResult(
            action=decision,
            risk_level=effective_risk,
            reason=reason,
            requires_approval=(decision == DecisionAction.REQUIRE_APPROVAL),
            suggested_approver=(
                "SRE-OnCall"
                if effective_risk in {RiskLevel.HIGH, RiskLevel.CRITICAL}
                else "Team-Lead"
            ),
            metadata={
                "avg_confidence": avg_confidence,
                "plan_preview": (plan[:100] + "...") if len(plan) > 100 else plan,
                "plan_risk": plan_risk.value,
                "request_risk": request_risk.value,
                "tool_risk": tool_risk.value,
                "tool_requires_approval": bool(tool_requires_approval),
                "tool_exists": bool(tool_exists),
                "execution_binding_complete": binding_complete,
                "execution_action": request_action or None,
                "execution_tool": request.get("tool_name") if request else None,
            },
        )

    @classmethod
    def _normalize_risk(cls, value: Optional[str]) -> RiskLevel:
        try:
            return RiskLevel(str(value or "low").lower())
        except ValueError:
            # Unknown tool risk must never make an action look safer.
            return RiskLevel.MEDIUM

    @classmethod
    def _max_risk(cls, *levels: RiskLevel) -> RiskLevel:
        return max(levels, key=lambda level: cls._RISK_ORDER[level])

    @classmethod
    def _assess_risk(cls, text: str) -> RiskLevel:
        value = str(text or "").lower()
        for word in cls.HIGH_RISK_KEYWORDS:
            if word in value:
                return RiskLevel.HIGH
        for word in cls.MEDIUM_RISK_KEYWORDS:
            if word in value:
                return RiskLevel.MEDIUM
        for word in cls.LOW_RISK_KEYWORDS:
            if word in value:
                return RiskLevel.LOW
        return RiskLevel.MEDIUM if value.strip() else RiskLevel.LOW

    @staticmethod
    def _calculate_avg_confidence(findings: List[Dict[str, Any]]) -> float:
        if not findings:
            return 0.0
        confidences = [
            float(f.get("confidence", 0.0))
            for f in findings
            if isinstance(f.get("confidence"), (int, float))
        ]
        return sum(confidences) / len(confidences) if confidences else 0.0

    @classmethod
    def _make_decision(
        cls,
        risk: RiskLevel,
        confidence: float,
        *,
        force_approval: bool = False,
    ) -> tuple[DecisionAction, str]:
        if risk == RiskLevel.CRITICAL:
            return DecisionAction.ESCALATE, "Critical risk. Immediate human intervention required."
        if risk == RiskLevel.HIGH:
            return DecisionAction.REQUIRE_APPROVAL, "High risk. Requires SRE approval."
        if force_approval:
            return DecisionAction.REQUIRE_APPROVAL, "Registered tool contract requires approval."
        if risk == RiskLevel.MEDIUM:
            if confidence >= 0.7:
                return DecisionAction.REQUIRE_APPROVAL, "Medium risk with good confidence. Requires team lead approval."
            return DecisionAction.REJECT, f"Medium risk but low confidence ({confidence:.2f}). Rejected."
        if risk == RiskLevel.LOW:
            if confidence >= 0.6:
                return DecisionAction.AUTO_EXECUTE, "Low-risk read-only/allowlisted action may auto-execute."
            return DecisionAction.REQUIRE_APPROVAL, f"Low risk but low confidence ({confidence:.2f}). Requires approval."
        return DecisionAction.REJECT, "Unclassified risk. Manual review required."
