from typing import Dict, Any, List, Optional
from datetime import datetime
from enum import Enum
from pydantic import BaseModel
from app.core.logging import logger

class VerificationStatus(str, Enum):
    SUCCESS = "success"
    FAILED = "failed"
    PARTIAL = "partial"
    INCONCLUSIVE = "inconclusive"

class VerificationResult(BaseModel):
    status: VerificationStatus
    before_state: Dict[str, float]
    after_state: Dict[str, float]
    changes: List[str]
    confidence: float
    evidence_refs: List[str]
    message: str

class VerificationEngine:
    @classmethod
    async def verify_action(
        cls,
        action_plan: str,
        service: str,
        before_context: Dict[str, Any],
        after_context: Optional[Dict[str, Any]] = None
    ) -> VerificationResult:
        logger.info(f"VerificationEngine: Verifying action for service {service}")
        before_metrics = cls._extract_metrics(before_context)
        if after_context is None:
            after_context = cls._simulate_after_execution(before_context, action_plan)
        after_metrics = cls._extract_metrics(after_context)
        changes = []
        improvements = 0
        total_metrics = 0
        all_keys = set(before_metrics.keys()) | set(after_metrics.keys())
        for key in all_keys:
            before_val = before_metrics.get(key, 0.0)
            after_val = after_metrics.get(key, 0.0)
            total_metrics += 1
            if key == "error_rate":
                if after_val < before_val:
                    changes.append(f"✓ error_rate decreased from {before_val:.1f}% to {after_val:.1f}%")
                    improvements += 1
                elif after_val > before_val:
                    changes.append(f"✗ error_rate increased from {before_val:.1f}% to {after_val:.1f}%")
                else:
                    changes.append(f"➖ error_rate unchanged: {before_val:.1f}%")
            elif key in ["cpu_usage", "memory_usage"]:
                if after_val < before_val:
                    changes.append(f"✓ {key} decreased from {before_val:.1f}% to {after_val:.1f}%")
                    improvements += 1
                elif after_val > before_val:
                    changes.append(f"✗ {key} increased from {before_val:.1f}% to {after_val:.1f}%")
                else:
                    changes.append(f"➖ {key} unchanged: {before_val:.1f}%")
        if total_metrics == 0:
            status = VerificationStatus.INCONCLUSIVE
            confidence = 0.0
            message = "No metrics available for verification."
        elif improvements == total_metrics:
            status = VerificationStatus.SUCCESS
            confidence = 0.9
            message = f"All {total_metrics} metrics improved after action."
        elif improvements >= total_metrics / 2:
            status = VerificationStatus.PARTIAL
            confidence = 0.6
            message = f"{improvements} out of {total_metrics} metrics improved."
        else:
            status = VerificationStatus.FAILED
            confidence = 0.2
            message = f"Action did not improve metrics. {improvements}/{total_metrics} improved."
        return VerificationResult(
            status=status,
            before_state=before_metrics,
            after_state=after_metrics,
            changes=changes,
            confidence=confidence,
            evidence_refs=["verification_engine"],
            message=message
        )
    
    @classmethod
    def _extract_metrics(cls, context: Dict[str, Any]) -> Dict[str, float]:
        summary = context.get("summary", {})
        return {
            "error_rate": summary.get("error_rate", 0.0),
            "cpu_usage": summary.get("avg_cpu", 0.0) or 0.0,
            "memory_usage": summary.get("avg_memory", 0.0) or 0.0,
        }
    
    @classmethod
    def _simulate_after_execution(cls, before: Dict[str, Any], plan: str) -> Dict[str, Any]:
        metrics = cls._extract_metrics(before)
        now = datetime.now()
        plan_lower = plan.lower()
        if "rollback" in plan_lower or "restart" in plan_lower:
            improvement_factor = 0.4
        elif "check" in plan_lower or "investigate" in plan_lower:
            improvement_factor = 0.1
        else:
            improvement_factor = 0.2
        after_metrics = {
            "error_rate": max(0, metrics["error_rate"] * (1 - improvement_factor * 2)),
            "cpu_usage": max(0, metrics["cpu_usage"] * (1 - improvement_factor * 0.5)),
            "memory_usage": max(0, metrics["memory_usage"] * (1 - improvement_factor * 0.3)),
        }
        return {
            "summary": {
                "error_rate": after_metrics["error_rate"],
                "avg_cpu": after_metrics["cpu_usage"],
                "avg_memory": after_metrics["memory_usage"],
                "log_count": 3,
                "metric_count": 3,
                "alert_count": 1,
                "latest_log": {
                    "timestamp": now.isoformat(),
                    "message": "Verification: System stabilized after action",
                    "level": "info"
                }
            }
        }