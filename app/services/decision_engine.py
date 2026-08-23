from typing import Dict, Any, List, Optional
from enum import Enum
from pydantic import BaseModel
from app.core.logging import logger

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
    metadata: Dict[str, Any] = {}

class DecisionEngine:
    HIGH_RISK_KEYWORDS = ["delete", "drop", "remove", "shutdown", "reboot", "rollback", "restore", "reset", "purge"]
    MEDIUM_RISK_KEYWORDS = ["restart", "redeploy", "scale", "update", "change", "modify", "config", "reload"]
    LOW_RISK_KEYWORDS = ["check", "investigate", "review", "monitor", "observe", "log", "query", "describe", "list"]

    @classmethod
    def evaluate_plan(cls, plan: str, findings: List[Dict[str, Any]]) -> DecisionResult:
        logger.info("Decision Engine: Evaluating plan...")
        risk_level = cls._assess_risk(plan)
        avg_confidence = cls._calculate_avg_confidence(findings)
        decision, reason = cls._make_decision(risk_level, avg_confidence, plan)
        logger.info(f"Decision: {decision.value} | Risk: {risk_level.value} | Reason: {reason}")
        return DecisionResult(
            action=decision,
            risk_level=risk_level,
            reason=reason,
            requires_approval=(decision == DecisionAction.REQUIRE_APPROVAL),
            suggested_approver="SRE-OnCall" if risk_level in [RiskLevel.HIGH, RiskLevel.CRITICAL] else "Team-Lead",
            metadata={"avg_confidence": avg_confidence, "plan_preview": plan[:100] + "..."}
        )

    @classmethod
    def _assess_risk(cls, plan: str) -> RiskLevel:
        plan_lower = plan.lower()
        for word in cls.HIGH_RISK_KEYWORDS:
            if word in plan_lower:
                return RiskLevel.HIGH
        for word in cls.MEDIUM_RISK_KEYWORDS:
            if word in plan_lower:
                return RiskLevel.MEDIUM
        for word in cls.LOW_RISK_KEYWORDS:
            if word in plan_lower:
                return RiskLevel.LOW
        return RiskLevel.MEDIUM

    @classmethod
    def _calculate_avg_confidence(cls, findings: List[Dict[str, Any]]) -> float:
        if not findings:
            return 0.0
        confidences = [f.get("confidence", 0.0) for f in findings if isinstance(f.get("confidence"), (int, float))]
        return sum(confidences) / len(confidences) if confidences else 0.0

    @classmethod
    def _make_decision(cls, risk: RiskLevel, confidence: float, plan: str) -> tuple[DecisionAction, str]:
        if risk == RiskLevel.CRITICAL:
            return DecisionAction.ESCALATE, "Critical risk. Immediate human intervention required."
        if risk == RiskLevel.HIGH:
            return DecisionAction.REQUIRE_APPROVAL, "High risk. Requires SRE approval."
        if risk == RiskLevel.MEDIUM:
            if confidence >= 0.7:
                return DecisionAction.REQUIRE_APPROVAL, "Medium risk with good confidence. Requires team lead approval."
            else:
                return DecisionAction.REJECT, f"Medium risk but low confidence ({confidence:.2f}). Rejected."
        if risk == RiskLevel.LOW:
            if confidence >= 0.6:
                return DecisionAction.AUTO_EXECUTE, f"Low risk. Auto-executing."
            else:
                return DecisionAction.REQUIRE_APPROVAL, f"Low risk but low confidence ({confidence:.2f}). Requires approval."
        return DecisionAction.REJECT, "Unclassified risk. Manual review required."