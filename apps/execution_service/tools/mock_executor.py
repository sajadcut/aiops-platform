# ============================================================
# FILE: app/tools/mock_executor.py
# ============================================================

import asyncio
import time
from typing import Any, Dict

from apps.execution_service.tools.base import BaseTool, ToolInput, ToolOutput
from domain.contracts.logging import logger


class MockExecutorTool(BaseTool):
    """
    Development-only executor.

    It never changes real infrastructure.
    It simulates an operational action and returns
    before/after metrics for verification.
    """

    @property
    def name(self) -> str:
        return "mock_executor"

    @property
    def risk_level(self) -> str:
        return "low"

    @property
    def requires_approval(self) -> bool:
        return False

    async def validate(
        self,
        input_data: ToolInput,
    ) -> bool:

        if not input_data.action:
            return False

        if not input_data.target:
            return False

        return True

    async def execute(
        self,
        input_data: ToolInput,
    ) -> ToolOutput:

        started = time.perf_counter()

        try:
            await asyncio.sleep(0.05)

            parameters: Dict[str, Any] = (
                input_data.parameters or {}
            )

            if parameters.get("force_failure") is True:
                return ToolOutput(
                    success=False,
                    result={
                        "simulated": True,
                        "status": "failed",
                        "action": input_data.action,
                        "target": input_data.target,
                    },
                    error="Forced mock execution failure",
                    execution_time=(
                        time.perf_counter() - started
                    ),
                )

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

            result = {
                "simulated": True,
                "status": "completed",
                "action": input_data.action,
                "target": input_data.target,
                "before": before,
                "after": after,
            }

            logger.info(
                f"Mock execution completed: "
                f"{input_data.action} "
                f"target={input_data.target}"
            )

            return ToolOutput(
                success=True,
                result=result,
                execution_time=(
                    time.perf_counter() - started
                ),
            )

        except Exception as exc:
            logger.exception(
                "Mock executor failed"
            )

            return ToolOutput(
                success=False,
                error=str(exc),
                execution_time=(
                    time.perf_counter() - started
                ),
            )