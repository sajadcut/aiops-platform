from typing import Dict, Any, List, Optional
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
    """
    Verification engine for post-execution validation.

    IMPORTANT:
    Verification must only evaluate a REAL post-execution context.

    If after_context is not provided, the engine MUST NOT simulate
    an execution result and MUST NOT report success.
    """

    @classmethod
    async def verify_action(
        cls,
        action_plan: str,
        service: str,
        before_context: Dict[str, Any],
        after_context: Optional[Dict[str, Any]] = None,
    ) -> VerificationResult:

        logger.info(
            f"VerificationEngine: "
            f"Verifying action for service {service}"
        )

        before_metrics = cls._extract_metrics(
            before_context
        )

        # ==========================================================
        # SAFETY RULE
        # ==========================================================
        #
        # No post-execution context means that no real action result
        # exists.
        #
        # NEVER manufacture an after-state.
        # NEVER claim success.
        #
        # ==========================================================

        if after_context is None:

            logger.warning(
                "VerificationEngine: "
                "No after_context provided. "
                "Verification is inconclusive."
            )

            return VerificationResult(
                status=VerificationStatus.INCONCLUSIVE,
                before_state=before_metrics,
                after_state={},
                changes=[],
                confidence=0.0,
                evidence_refs=[],
                message=(
                    "Verification is inconclusive because "
                    "no post-execution context was provided. "
                    "No action result is available."
                ),
            )

        # ==========================================================
        # REAL POST-EXECUTION CONTEXT
        # ==========================================================

        after_metrics = cls._extract_metrics(
            after_context
        )

        if not before_metrics:
            logger.warning(
                "VerificationEngine: "
                "No before metrics available."
            )

        if not after_metrics:
            logger.warning(
                "VerificationEngine: "
                "No after metrics available."
            )

            return VerificationResult(
                status=VerificationStatus.INCONCLUSIVE,
                before_state=before_metrics,
                after_state=after_metrics,
                changes=[],
                confidence=0.0,
                evidence_refs=[
                    "post_execution_observability"
                ],
                message=(
                    "Post-execution context was provided, "
                    "but no comparable metrics were found."
                ),
            )

        changes: List[str] = []

        improvements = 0
        regressions = 0
        comparable_metrics = 0

        all_keys = (
            set(before_metrics.keys())
            & set(after_metrics.keys())
        )

        for key in sorted(all_keys):

            before_value = float(
                before_metrics[key]
            )

            after_value = float(
                after_metrics[key]
            )

            comparable_metrics += 1

            # ------------------------------------------------------
            # Error rate
            # Lower is better.
            # ------------------------------------------------------

            if key == "error_rate":

                if after_value < before_value:

                    improvements += 1

                    changes.append(
                        (
                            f"error_rate decreased "
                            f"from {before_value:.2f}% "
                            f"to {after_value:.2f}%"
                        )
                    )

                elif after_value > before_value:

                    regressions += 1

                    changes.append(
                        (
                            f"error_rate increased "
                            f"from {before_value:.2f}% "
                            f"to {after_value:.2f}%"
                        )
                    )

                else:

                    changes.append(
                        (
                            f"error_rate unchanged at "
                            f"{before_value:.2f}%"
                        )
                    )

            # ------------------------------------------------------
            # CPU / Memory
            # Lower is considered an improvement.
            # ------------------------------------------------------

            elif key in (
                "cpu_usage",
                "memory_usage",
            ):

                if after_value < before_value:

                    improvements += 1

                    changes.append(
                        (
                            f"{key} decreased "
                            f"from {before_value:.2f}% "
                            f"to {after_value:.2f}%"
                        )
                    )

                elif after_value > before_value:

                    regressions += 1

                    changes.append(
                        (
                            f"{key} increased "
                            f"from {before_value:.2f}% "
                            f"to {after_value:.2f}%"
                        )
                    )

                else:

                    changes.append(
                        (
                            f"{key} unchanged at "
                            f"{before_value:.2f}%"
                        )
                    )

        # ==========================================================
        # No comparable metrics
        # ==========================================================

        if comparable_metrics == 0:

            return VerificationResult(
                status=VerificationStatus.INCONCLUSIVE,
                before_state=before_metrics,
                after_state=after_metrics,
                changes=changes,
                confidence=0.0,
                evidence_refs=[
                    "post_execution_observability"
                ],
                message=(
                    "Post-execution context was available, "
                    "but no comparable metrics could be "
                    "used for verification."
                ),
            )

        # ==========================================================
        # Verification decision
        # ==========================================================

        # All comparable metrics improved.
        if (
            improvements == comparable_metrics
            and regressions == 0
        ):

            status = VerificationStatus.SUCCESS
            confidence = 0.90

            message = (
                f"All {comparable_metrics} comparable "
                "metrics improved after the executed action."
            )

        # Some improved, some did not.
        elif (
            improvements > 0
            and regressions == 0
        ):

            status = VerificationStatus.PARTIAL

            confidence = (
                improvements
                / comparable_metrics
            )

            message = (
                f"{improvements} of "
                f"{comparable_metrics} comparable "
                "metrics improved after the action. "
                "Verification is partial."
            )

        # Some improved but others regressed.
        elif (
            improvements > 0
            and regressions > 0
        ):

            status = VerificationStatus.PARTIAL

            confidence = 0.40

            message = (
                f"{improvements} metrics improved and "
                f"{regressions} metrics regressed. "
                "The action produced mixed results."
            )

        # Nothing improved.
        else:

            status = VerificationStatus.FAILED
            confidence = 0.20

            message = (
                "The executed action did not produce "
                "measurable improvement in the "
                f"{comparable_metrics} comparable metrics."
            )

        return VerificationResult(
            status=status,
            before_state=before_metrics,
            after_state=after_metrics,
            changes=changes,
            confidence=confidence,
            evidence_refs=[
                "post_execution_observability"
            ],
            message=message,
        )

    # ==============================================================
    # Metrics extraction
    # ==============================================================

    @classmethod
    def _extract_metrics(
        cls,
        context: Dict[str, Any],
    ) -> Dict[str, float]:

        if not isinstance(
            context,
            dict,
        ):
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

        metrics: Dict[str, float] = {}

        # ----------------------------------------------------------
        # Error rate
        # ----------------------------------------------------------

        error_rate = summary.get(
            "error_rate"
        )

        if error_rate is not None:

            try:

                metrics["error_rate"] = float(
                    error_rate
                )

            except (
                TypeError,
                ValueError,
            ):

                logger.warning(
                    (
                        "VerificationEngine: "
                        f"Invalid error_rate value: "
                        f"{error_rate}"
                    )
                )

        # ----------------------------------------------------------
        # CPU
        # ----------------------------------------------------------

        avg_cpu = summary.get(
            "avg_cpu"
        )

        if avg_cpu is not None:

            try:

                metrics["cpu_usage"] = float(
                    avg_cpu
                )

            except (
                TypeError,
                ValueError,
            ):

                logger.warning(
                    (
                        "VerificationEngine: "
                        f"Invalid avg_cpu value: "
                        f"{avg_cpu}"
                    )
                )

        # ----------------------------------------------------------
        # Memory
        # ----------------------------------------------------------

        avg_memory = summary.get(
            "avg_memory"
        )

        if avg_memory is not None:

            try:

                metrics["memory_usage"] = float(
                    avg_memory
                )

            except (
                TypeError,
                ValueError,
            ):

                logger.warning(
                    (
                        "VerificationEngine: "
                        f"Invalid avg_memory value: "
                        f"{avg_memory}"
                    )
                )

        return metrics