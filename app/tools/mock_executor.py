import asyncio
import time
from typing import Dict, Any

from app.tools.base import BaseTool, ToolInput, ToolOutput
from app.core.logging import logger


class MockExecutorTool(BaseTool):
    """
    Development-only execution tool.

    This tool NEVER changes a real system.

    It simulates an operational action and returns a deterministic
    post-execution result that can be consumed by VerificationEngine.

    Intended for:
        - local development
        - integration tests
        - workflow validation
        - approval/execution testing

    It must NOT be used as a production executor.
    """

    @property
    def name(self) -> str:
        return "mock_executor"

    @property
    def risk_level(self) -> str:
        return "low"

    @property
    def requires_approval(self) -> bool:
        """
        Mock execution is intentionally low risk.

        This allows us to test the execution pipeline without
        requiring real production approval.
        """

        return False

    async def validate(
        self,
        input_data: ToolInput,
    ) -> bool:

        if not input_data.action:
            return False

        if not input_data.target:
            return False

        if input_data.timeout is not None:
            if input_data.timeout <= 0:
                return False

        return True

    async def execute(
        self,
        input_data: ToolInput,
    ) -> ToolOutput:

        started_at = time.perf_counter()

        logger.info(
            "MockExecutorTool: "
            f"executing action='{input_data.action}' "
            f"target='{input_data.target}'"
        )

        try:

            # ------------------------------------------------------
            # Simulate execution latency
            # ------------------------------------------------------

            await asyncio.sleep(0.05)

            parameters = dict(
                input_data.parameters or {}
            )

            # ------------------------------------------------------
            # Deterministic failure switch for testing
            # ------------------------------------------------------

            force_failure = bool(
                parameters.get(
                    "force_failure",
                    False,
                )
            )

            if force_failure:

                execution_time = (
                    time.perf_counter()
                    - started_at
                )

                return ToolOutput(
                    success=False,
                    result={
                        "action": input_data.action,
                        "target": input_data.target,
                        "simulated": True,
                        "status": "failed",
                    },
                    error="Mock execution failure requested.",
                    execution_time=execution_time,
                )

            # ------------------------------------------------------
            # Simulated operational effect
            # ------------------------------------------------------

            before = {
                "error_rate": float(
                    parameters.get(
                        "before_error_rate",
                        15.6,
                    )
                ),
                "avg_cpu": float(
                    parameters.get(
                        "before_cpu",
                        75.0,
                    )
                ),
                "avg_memory": float(
                    parameters.get(
                        "before_memory",
                        85.0,
                    )
                ),
            }

            after = {
                "error_rate": float(
                    parameters.get(
                        "after_error_rate",
                        4.2,
                    )
                ),
                "avg_cpu": float(
                    parameters.get(
                        "after_cpu",
                        62.0,
                    )
                ),
                "avg_memory": float(
                    parameters.get(
                        "after_memory",
                        68.0,
                    )
                ),
            }

            execution_time = (
                time.perf_counter()
                - started_at
            )

            logger.info(
                "MockExecutorTool: "
                f"action='{input_data.action}' "
                f"completed successfully"
            )

            return ToolOutput(
                success=True,
                result={
                    "action": input_data.action,
                    "target": input_data.target,
                    "simulated": True,
                    "status": "completed",
                    "before": before,
                    "after": after,
                    "parameters": parameters,
                },
                error=None,
                execution_time=execution_time,
            )

        except Exception as exc:

            execution_time = (
                time.perf_counter()
                - started_at
            )

            logger.exception(
                "MockExecutorTool failed"
            )

            return ToolOutput(
                success=False,
                result=None,
                error=str(exc),
                execution_time=execution_time,
            )