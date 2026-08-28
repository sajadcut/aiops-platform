from typing import Dict, Any, Optional
from uuid import uuid4

from pydantic import BaseModel, Field

from domain.contracts.logging import logger
from apps.execution_service.tools.base import ToolInput
from apps.execution_service.tools.registry import tool_registry


class ExecutionRequest(BaseModel):
    execution_id: str = Field(default_factory=lambda: str(uuid4()))
    tool_name: str
    action: str
    target: str
    parameters: Dict[str, Any] = Field(default_factory=dict)
    timeout: int = 30
    agent_name: str = "execution_service"
    approval_granted: bool = False
    approval_id: Optional[str] = None


class ExecutionResult(BaseModel):
    success: bool
    execution_id: str
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
    async def execute(cls, request: ExecutionRequest) -> ExecutionResult:
        logger.info(
            "execution_requested",
            execution_id=request.execution_id,
            tool=request.tool_name,
            action=request.action,
            target=request.target,
            approval_id=request.approval_id,
            agent=request.agent_name,
        )

        tool = tool_registry.get_tool(request.tool_name)
        if tool is None:
            return ExecutionResult(
                success=False,
                execution_id=request.execution_id,
                tool_name=request.tool_name,
                action=request.action,
                target=request.target,
                execution_blocked=True,
                reason="tool_not_found",
                error="requested tool is not registered",
                approval_id=request.approval_id,
            )

        if tool.requires_approval and not request.approval_granted:
            return ExecutionResult(
                success=False,
                execution_id=request.execution_id,
                tool_name=request.tool_name,
                action=request.action,
                target=request.target,
                execution_blocked=True,
                reason="approval_required",
                error="approval required",
                approval_id=request.approval_id,
            )

        if tool.requires_approval and not request.approval_id:
            return ExecutionResult(
                success=False,
                execution_id=request.execution_id,
                tool_name=request.tool_name,
                action=request.action,
                target=request.target,
                execution_blocked=True,
                reason="approval_id_required",
                error="persisted approval_id required",
                approval_id=request.approval_id,
            )

        tool_input = ToolInput(
            action=request.action,
            target=request.target,
            parameters=request.parameters,
            timeout=request.timeout,
            approval_id=request.approval_id,
        )

        validation = await tool.validate(tool_input)
        if not validation:
            return ExecutionResult(
                success=False,
                execution_id=request.execution_id,
                tool_name=request.tool_name,
                action=request.action,
                target=request.target,
                execution_blocked=True,
                reason="validation_failed",
                error="tool input validation failed",
                approval_id=request.approval_id,
            )

        result = await tool_registry.execute_tool(
            tool_name=request.tool_name,
            input_data=tool_input,
            agent_name=request.agent_name,
            approval_granted=request.approval_granted,
            approval_id=request.approval_id,
            execution_id=request.execution_id,
        )

        return ExecutionResult(
            success=bool(result.get("success", False)),
            execution_id=request.execution_id,
            tool_name=request.tool_name,
            action=request.action,
            target=request.target,
            execution_blocked=bool(result.get("execution_blocked", False)),
            reason=result.get("reason"),
            result=result.get("result"),
            error=result.get("error"),
            execution_time=result.get("execution_time"),
            approval_id=request.approval_id,
        )
