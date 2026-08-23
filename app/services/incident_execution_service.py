# ============================================================
# FILE: app/services/incident_execution_service.py
# ============================================================

from typing import Any, Dict, Optional
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

from app.services.execution_service import (
    ExecutionService,
    ExecutionRequest,
    ExecutionResult,
)

from app.services.verification_engine import (
    VerificationEngine,
    VerificationResult,
)

from app.services.incident_memory_service import (
    IncidentMemoryService,
)


class IncidentExecutionService:

    @classmethod
    async def execute_and_verify(
        cls,
        db: AsyncSession,
        incident_id: Optional[UUID],
        service: str,
        action: str,
        target: str,
        before_context: Dict[str, Any],
        execution_parameters: Dict[str, Any],
        tool_name: str = "mock_executor",
        approval_granted: bool = False,
        approval_id: Optional[str] = None,
        root_cause: Optional[str] = None,
        environment: Optional[str] = None,
    ) -> Dict[str, Any]:

        request = ExecutionRequest(
            tool_name=tool_name,
            action=action,
            target=target,
            parameters=execution_parameters,
            approval_granted=approval_granted,
            approval_id=approval_id,
            agent_name="incident_execution_service",
        )

        execution: ExecutionResult = (
            await ExecutionService.execute(
                request
            )
        )

        if not execution.success:

            return {
                "execution": execution.model_dump(),
                "verification": None,
                "memory_id": None,
            }

        execution_result = (
            execution.result or {}
        )

        after = execution_result.get(
            "after"
        )

        if not isinstance(after, dict):
            after = {}

        after_context = {
            "summary": {
                "error_rate": after.get(
                    "error_rate"
                ),
                "avg_cpu": after.get(
                    "avg_cpu"
                ),
                "avg_memory": after.get(
                    "avg_memory"
                ),
            }
        }

        verification: VerificationResult = (
            await VerificationEngine.verify_action(
                action_plan=action,
                service=service,
                before_context=before_context,
                after_context=after_context,
            )
        )

        memory_id = None

        if verification.status.value != "inconclusive":

            memory_id = (
                await IncidentMemoryService
                .save_verified_incident(
                    db=db,
                    incident_id=incident_id,
                    service=service,
                    pattern=(
                        f"{service}: {action}"
                    ),
                    symptoms={
                        "before": (
                            verification.before_state
                        )
                    },
                    root_cause=root_cause,
                    action=action,
                    verification_status=(
                        verification.status.value
                    ),
                    outcome=verification.message,
                    environment=environment,
                )
            )

        return {
            "execution": execution.model_dump(),
            "verification": (
                verification.model_dump()
            ),
            "memory_id": (
                str(memory_id)
                if memory_id
                else None
            ),
        }