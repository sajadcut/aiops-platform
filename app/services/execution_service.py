from typing import Dict, Any, Optional

from pydantic import BaseModel, Field

from app.core.logging import logger
from app.tools.base import ToolInput
from app.tools.registry import tool_registry


class ExecutionRequest(BaseModel):
    """
    Standard request for controlled operational execution.
    """

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
    """
    Standard result returned by ExecutionService.
    """

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
    """
    Controlled execution boundary.

    No Agent should execute an operational Tool directly.

    Flow:

        Decision
            ↓
        Approval
            ↓
        ExecutionService
            ↓
        ToolRegistry
            ↓
        Tool
            ↓
        ExecutionResult
    """

    @classmethod
    async def execute(
        cls,
        request: ExecutionRequest,
    ) -> ExecutionResult:

        logger.info(
            "ExecutionService: "
            f"request received "
            f"tool={request.tool_name}, "
            f"action={request.action}, "
            f"target={request.target}"
        )

        # ----------------------------------------------------------
        # Tool lookup
        # ----------------------------------------------------------

        tool = tool_registry.get_tool(
            request.tool_name
        )

        if tool is None:

            message = (
                f"Tool '{request.tool_name}' "
                "is not registered."
            )

            logger.warning(
                f"ExecutionService: {message}"
            )

            return ExecutionResult(
                success=False,
                tool_name=request.tool_name,
                action=request.action,
                target=request.target,
                execution_blocked=True,
                reason="tool_not_found",
                error=message,
                approval_id=request.approval_id,
            )

        # ----------------------------------------------------------
        # Approval guard
        # ----------------------------------------------------------

        if (
            tool.requires_approval
            and not request.approval_granted
        ):

            message = (
                f"Tool '{request.tool_name}' "
                "requires approval."
            )

            logger.warning(
                "ExecutionService: "
                f"execution blocked - {message}"
            )

            return ExecutionResult(
                success=False,
                tool_name=request.tool_name,
                action=request.action,
                target=request.target,
                execution_blocked=True,
                reason="approval_required",
                error=message,
                approval_id=request.approval_id,
            )

        # ----------------------------------------------------------
        # Build ToolInput
        # ----------------------------------------------------------

        tool_input = ToolInput(
            action=request.action,
            target=request.target,
            parameters=request.parameters,
            timeout=request.timeout,
        )

        # ----------------------------------------------------------
        # Execute through Registry
        # ----------------------------------------------------------

        result = await tool_registry.execute_tool(
            tool_name=request.tool_name,
            input_data=tool_input,
            agent_name=request.agent_name,
            approval_granted=request.approval_granted,
            approval_id=request.approval_id,
        )

        # ----------------------------------------------------------
        # Normalize result
        # ----------------------------------------------------------

        success = bool(
            result.get(
                "success",
                False,
            )
        )

        execution_blocked = bool(
            result.get(
                "execution_blocked",
                False,
            )
        )

        return ExecutionResult(
            success=success,
            tool_name=request.tool_name,
            action=request.action,
            target=request.target,
            execution_blocked=execution_blocked,
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
            approval_id=result.get(
                "approval_id",
                request.approval_id,
            ),
        )