# ============================================================
# FILE 3: app/services/verification_engine.py
# ============================================================

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
        after_context: Optional[
            Dict[str, Any]
        ] = None,
    ) -> VerificationResult:

        logger.info(
            f"Verification started: "
            f"service={service}"
        )

        before_metrics = (
            cls._extract_metrics(
                before_context
            )
        )

        if after_context is None:
            return VerificationResult(
                status=(
                    VerificationStatus
                    .INCONCLUSIVE
                ),
                before_state=before_metrics,
                after_state={},
                changes=[],
                confidence=0.0,
                evidence_refs=[],
                message=(
                    "No post-execution "
                    "context was supplied."
                ),
            )

        after_metrics = (
            cls._extract_metrics(
                after_context
            )
        )

        if not before_metrics:
            return VerificationResult(
                status=(
                    VerificationStatus
                    .INCONCLUSIVE
                ),
                before_state={},
                after_state=after_metrics,
                changes=[],
                confidence=0.0,
                evidence_refs=[],
                message=(
                    "No pre-execution "
                    "metrics were available."
                ),
            )

        if not after_metrics:
            return VerificationResult(
                status=(
                    VerificationStatus
                    .INCONCLUSIVE
                ),
                before_state=before_metrics,
                after_state={},
                changes=[],
                confidence=0.0,
                evidence_refs=[],
                message=(
                    "No post-execution "
                    "metrics were available."
                ),
            )

        changes = []

        improvements = 0
        regressions = 0
        comparable = 0

        for key in sorted(
            set(before_metrics)
            & set(after_metrics)
        ):

            before_value = (
                before_metrics[key]
            )

            after_value = (
                after_metrics[key]
            )

            comparable += 1

            if after_value < before_value:

                improvements += 1

                changes.append(
                    f"{key}: "
                    f"{before_value:.2f} -> "
                    f"{after_value:.2f} "
                    f"(improved)"
                )

            elif after_value > before_value:

                regressions += 1

                changes.append(
                    f"{key}: "
                    f"{before_value:.2f} -> "
                    f"{after_value:.2f} "
                    f"(worsened)"
                )

            else:

                changes.append(
                    f"{key}: "
                    f"{before_value:.2f} -> "
                    f"{after_value:.2f} "
                    f"(unchanged)"
                )

        if comparable == 0:

            return VerificationResult(
                status=(
                    VerificationStatus
                    .INCONCLUSIVE
                ),
                before_state=before_metrics,
                after_state=after_metrics,
                changes=changes,
                confidence=0.0,
                evidence_refs=[
                    "before_context",
                    "after_context",
                ],
                message=(
                    "No comparable metrics "
                    "were found."
                ),
            )

        if improvements == comparable:

            status = (
                VerificationStatus.SUCCESS
            )

            confidence = 0.90

            message = (
                f"All {comparable} "
                "comparable metrics improved."
            )

        elif improvements > regressions:

            status = (
                VerificationStatus.PARTIAL
            )

            confidence = 0.65

            message = (
                f"{improvements} metrics improved "
                f"and {regressions} worsened."
            )

        elif regressions > improvements:

            status = (
                VerificationStatus.FAILED
            )

            confidence = 0.25

            message = (
                f"{regressions} metrics worsened "
                f"and {improvements} improved."
            )

        else:

            status = (
                VerificationStatus.PARTIAL
            )

            confidence = 0.50

            message = (
                "The result is mixed and "
                "requires further observation."
            )

        return VerificationResult(
            status=status,
            before_state=before_metrics,
            after_state=after_metrics,
            changes=changes,
            confidence=confidence,
            evidence_refs=[
                "before_context",
                "after_context",
            ],
            message=message,
        )

    @classmethod
    def _extract_metrics(
        cls,
        context: Dict[str, Any],
    ) -> Dict[str, float]:

        if not context:
            return {}

        summary = context.get(
            "summary",
            {},
        )

        if not isinstance(
            summary,
            dict,
        ):
            return {}

        result = {}

        error_rate = summary.get(
            "error_rate"
        )

        cpu = summary.get(
            "avg_cpu"
        )

        memory = summary.get(
            "avg_memory"
        )

        if error_rate is not None:

            try:
                result[
                    "error_rate"
                ] = float(
                    error_rate
                )
            except (
                TypeError,
                ValueError,
            ):
                pass

        if cpu is not None:

            try:
                result[
                    "cpu_usage"
                ] = float(cpu)
            except (
                TypeError,
                ValueError,
            ):
                pass

        if memory is not None:

            try:
                result[
                    "memory_usage"
                ] = float(memory)
            except (
                TypeError,
                ValueError,
            ):
                pass

        return result