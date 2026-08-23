# ============================================================
# FILE 2: app/services/execution_service.py
# ============================================================

from typing import Dict, Any, Optional

from pydantic import BaseModel, Field

from domain.contracts.logging import logger
from apps.execution_service.tools.base import ToolInput
from apps.execution_service.tools.registry import tool_registry


class ExecutionRequest(BaseModel):
    tool_name: str
    action: str
    target: str

    parameters: Dict[str, Any] = Field(
        default_factory=dict
    )

    timeout: int = 30

    agent_name: str = "execution_service"

    approval_granted: bool = False

    approval_id: Optional[str] = None


class ExecutionResult(BaseModel):
    success: bool

    tool_name: str
    action: str
    target: str

    execution_blocked: bool = False

    reason: Optional[str] = None

    result: Optional[Dict[str, Any]] = None

    error: Optional[str] = None

    execution_time: Optional[float] = None

    approval_id: Optional[str] = None


class ExecutionService:

    @classmethod
    async def execute(
        cls,
        request: ExecutionRequest,
    ) -> ExecutionResult:

        logger.info(
            f"Execution request: "
            f"tool={request.tool_name}, "
            f"action={request.action}, "
            f"target={request.target}"
        )

        tool = tool_registry.get_tool(
            request.tool_name
        )

        if tool is None:
            return ExecutionResult(
                success=False,
                tool_name=request.tool_name,
                action=request.action,
                target=request.target,
                execution_blocked=True,
                reason="tool_not_found",
                error=(
                    f"Tool '{request.tool_name}' "
                    "is not registered"
                ),
                approval_id=request.approval_id,
            )

        if (
            tool.requires_approval
            and not request.approval_granted
        ):
            return ExecutionResult(
                success=False,
                tool_name=request.tool_name,
                action=request.action,
                target=request.target,
                execution_blocked=True,
                reason="approval_required",
                error=(
                    f"Tool '{request.tool_name}' "
                    "requires approval"
                ),
                approval_id=request.approval_id,
            )

        tool_input = ToolInput(
            action=request.action,
            target=request.target,
            parameters=request.parameters,
            timeout=request.timeout,
        )

        validation = await tool.validate(
            tool_input
        )

        if not validation:
            return ExecutionResult(
                success=False,
                tool_name=request.tool_name,
                action=request.action,
                target=request.target,
                execution_blocked=True,
                reason="validation_failed",
                error="Tool input validation failed",
                approval_id=request.approval_id,
            )

        result = await tool_registry.execute_tool(
            tool_name=request.tool_name,
            input_data=tool_input,
            agent_name=request.agent_name,
        )

        return ExecutionResult(
            success=bool(
                result.get(
                    "success",
                    False,
                )
            ),
            tool_name=request.tool_name,
            action=request.action,
            target=request.target,
            execution_blocked=bool(
                result.get(
                    "execution_blocked",
                    False,
                )
            ),
            reason=result.get(
                "reason"
            ),
            result=result.get(
                "result"
            ),
            error=result.get(
                "error"
            ),
            execution_time=result.get(
                "execution_time"
            ),
            approval_id=request.approval_id,
        )