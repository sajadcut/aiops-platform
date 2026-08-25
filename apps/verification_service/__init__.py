from typing import Dict, Any, List, Optional
from enum import Enum

from pydantic import BaseModel

from domain.contracts.logging import logger


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
        after_context: Optional[Dict[str, Any]] = None,
    ) -> VerificationResult:
        logger.info(f"Verification started: service={service}")
        before_metrics = cls._extract_metrics(before_context)

        if after_context is None:
            return VerificationResult(
                status=VerificationStatus.INCONCLUSIVE,
                before_state=before_metrics,
                after_state={},
                changes=[],
                confidence=0.0,
                evidence_refs=[],
                message="No post-execution context was supplied.",
            )

        after_metrics = cls._extract_metrics(after_context)
        if not before_metrics:
            return VerificationResult(
                status=VerificationStatus.INCONCLUSIVE,
                before_state={},
                after_state=after_metrics,
                changes=[],
                confidence=0.0,
                evidence_refs=cls._evidence_refs(before_context),
                message="No pre-execution metrics were available.",
            )

        if not after_metrics:
            return VerificationResult(
                status=VerificationStatus.INCONCLUSIVE,
                before_state=before_metrics,
                after_state={},
                changes=[],
                confidence=0.0,
                evidence_refs=cls._evidence_refs(after_context),
                message="No post-execution metrics were available.",
            )

        changes: List[str] = []
        improvements = 0
        regressions = 0
        comparable = 0

        for key in sorted(set(before_metrics) & set(after_metrics)):
            before_value = before_metrics[key]
            after_value = after_metrics[key]
            comparable += 1
            if after_value < before_value:
                improvements += 1
                changes.append(f"{key}: {before_value:.2f} -> {after_value:.2f} (improved)")
            elif after_value > before_value:
                regressions += 1
                changes.append(f"{key}: {before_value:.2f} -> {after_value:.2f} (worsened)")
            else:
                changes.append(f"{key}: {before_value:.2f} -> {after_value:.2f} (unchanged)")

        if comparable == 0:
            return VerificationResult(
                status=VerificationStatus.INCONCLUSIVE,
                before_state=before_metrics,
                after_state=after_metrics,
                changes=changes,
                confidence=0.0,
                evidence_refs=cls._evidence_refs(before_context) + cls._evidence_refs(after_context),
                message="No comparable metrics were found.",
            )

        if improvements == comparable:
            status = VerificationStatus.SUCCESS
            confidence = 0.90
            message = f"All {comparable} comparable metrics improved."
        elif improvements > regressions:
            status = VerificationStatus.PARTIAL
            confidence = 0.65
            message = f"{improvements} metrics improved and {regressions} worsened."
        elif regressions > improvements:
            status = VerificationStatus.FAILED
            confidence = 0.25
            message = f"{regressions} metrics worsened and {improvements} improved."
        else:
            status = VerificationStatus.PARTIAL
            confidence = 0.50
            message = "The result is mixed and requires further observation."

        return VerificationResult(
            status=status,
            before_state=before_metrics,
            after_state=after_metrics,
            changes=changes,
            confidence=confidence,
            evidence_refs=cls._evidence_refs(before_context) + cls._evidence_refs(after_context),
            message=message,
        )

    @classmethod
    def _extract_metrics(cls, context: Dict[str, Any]) -> Dict[str, float]:
        if not context:
            return {}
        result: Dict[str, float] = {}
        summary = context.get("summary", {})
        if isinstance(summary, dict):
            cls._add_numeric(result, "error_rate", summary.get("error_rate"))
            cls._add_numeric(result, "cpu_usage", summary.get("avg_cpu"))
            cls._add_numeric(result, "memory_usage", summary.get("avg_memory"))

        live_evidence = context.get("live_evidence", {})
        evidence_items = live_evidence.get("evidence", []) if isinstance(live_evidence, dict) else []
        for item in evidence_items:
            raw = item.get("raw_data", {}) if isinstance(item, dict) else {}
            if not isinstance(raw, dict):
                continue
            name = str(raw.get("name") or "").lower()
            value = raw.get("value")
            if value is None:
                continue
            try:
                numeric = float(value)
            except (TypeError, ValueError):
                continue
            if any(token in name for token in ("error_rate", "5xx", "http_error", "error")):
                result.setdefault("error_rate", numeric)
            elif any(token in name for token in ("cpu", "processor")):
                result.setdefault("cpu_usage", numeric)
            elif any(token in name for token in ("memory", "mem_")):
                result.setdefault("memory_usage", numeric)
        return result

    @staticmethod
    def _add_numeric(target: Dict[str, float], name: str, value: Any) -> None:
        if value is None:
            return
        try:
            target[name] = float(value)
        except (TypeError, ValueError):
            return

    @staticmethod
    def _evidence_refs(context: Optional[Dict[str, Any]]) -> List[str]:
        if not context:
            return []
        live_evidence = context.get("live_evidence", {})
        refs: List[str] = []
        if isinstance(live_evidence, dict):
            for item in live_evidence.get("evidence", []):
                if isinstance(item, dict) and item.get("reference"):
                    refs.append(str(item["reference"]))
        return refs
