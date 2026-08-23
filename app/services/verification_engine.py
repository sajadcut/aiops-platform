# ============================================================
# FILE: app/services/verification_engine.py
# ============================================================

from enum import Enum
from typing import Any, Dict, List, Optional

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
        after_context: Optional[
            Dict[str, Any]
        ] = None,
    ) -> VerificationResult:

        logger.info(
            f"Verification started: "
            f"service={service}"
        )

        before = cls._extract_metrics(
            before_context
        )

        if after_context is None:
            return VerificationResult(
                status=VerificationStatus.INCONCLUSIVE,
                before_state=before,
                after_state={},
                changes=[],
                confidence=0.0,
                evidence_refs=[],
                message=(
                    "No post-execution context "
                    "was supplied."
                ),
            )

        after = cls._extract_metrics(
            after_context
        )

        if not before or not after:
            return VerificationResult(
                status=VerificationStatus.INCONCLUSIVE,
                before_state=before,
                after_state=after,
                changes=[],
                confidence=0.0,
                evidence_refs=[],
                message=(
                    "Insufficient metrics "
                    "for verification."
                ),
            )

        changes: List[str] = []

        improved = 0
        worsened = 0
        comparable = 0

        for metric in sorted(
            set(before) & set(after)
        ):

            old = before[metric]
            new = after[metric]

            comparable += 1

            if new < old:
                improved += 1

                changes.append(
                    f"{metric}: "
                    f"{old:.2f} -> {new:.2f} "
                    f"(improved)"
                )

            elif new > old:
                worsened += 1

                changes.append(
                    f"{metric}: "
                    f"{old:.2f} -> {new:.2f} "
                    f"(worsened)"
                )

            else:
                changes.append(
                    f"{metric}: "
                    f"{old:.2f} -> {new:.2f} "
                    f"(unchanged)"
                )

        if comparable == 0:
            status = VerificationStatus.INCONCLUSIVE
            confidence = 0.0
            message = (
                "No comparable metrics were found."
            )

        elif improved == comparable:
            status = VerificationStatus.SUCCESS
            confidence = 0.90
            message = (
                f"All {comparable} comparable "
                "metrics improved."
            )

        elif improved > worsened:
            status = VerificationStatus.PARTIAL
            confidence = 0.65
            message = (
                f"{improved} metrics improved and "
                f"{worsened} worsened."
            )

        else:
            status = VerificationStatus.FAILED
            confidence = 0.25
            message = (
                "The post-execution state did "
                "not improve sufficiently."
            )

        return VerificationResult(
            status=status,
            before_state=before,
            after_state=after,
            changes=changes,
            confidence=confidence,
            evidence_refs=[
                "before_context",
                "after_context",
            ],
            message=message,
        )

    @staticmethod
    def _extract_metrics(
        context: Dict[str, Any],
    ) -> Dict[str, float]:

        if not context:
            return {}

        summary = context.get(
            "summary",
            {},
        )

        if not isinstance(summary, dict):
            return {}

        result: Dict[str, float] = {}

        mapping = {
            "error_rate": "error_rate",
            "avg_cpu": "avg_cpu",
            "cpu": "avg_cpu",
            "avg_memory": "avg_memory",
            "memory": "avg_memory",
        }

        for source, target in mapping.items():

            value = summary.get(source)

            if value is not None:
                try:
                    result[target] = float(value)
                except (
                    TypeError,
                    ValueError,
                ):
                    continue

        return result