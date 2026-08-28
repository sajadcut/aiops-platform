from typing import Dict, Any, Optional

from pydantic import BaseModel, Field

from domain.contracts.logging import logger
from apps.execution_service.capability import ExecutionCapabilityError, verify_execution_capability
from apps.execution_service.tools.base import ToolInput
from apps.execution_service.tools.registry import tool_registry


class ExecutionRequest(BaseModel):
    tool_name: str
    action: str
    target: str
    parameters: Dict[str, Any] = Field(default_factory=dict)
    timeout: int = 30
    agent_name: str = "execution_service"
    incident_id: Optional[str] = None
    approval_granted: bool = False  # compatibility only; never trusted as authorization
    approval_id: Optional[str] = None
    execution_capability: Optional[str] = None
    runbook_id: Optional[str] = None
    runbook_version: Optional[str] = None
    rollback: bool = False


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
    async def execute(cls, request: ExecutionRequest) -> ExecutionResult:
        logger.info(
            "execution_request_received",
            tool=request.tool_name,
            action=request.action,
            target=request.target,
            incident_id=request.incident_id,
            approval_id=request.approval_id,
        )

        tool = tool_registry.get_tool(request.tool_name)
        if tool is None:
            return ExecutionResult(
                success=False, tool_name=request.tool_name, action=request.action, target=request.target,
                execution_blocked=True, reason="tool_not_found", error=f"Tool '{request.tool_name}' is not registered",
                approval_id=request.approval_id,
            )

        if tool.requires_approval:
            if not request.approval_id:
                return ExecutionResult(
                    success=False, tool_name=request.tool_name, action=request.action, target=request.target,
                    execution_blocked=True, reason="approval_id_required",
                    error="Approved execution requires a persisted approval_id", approval_id=request.approval_id,
                )
            if not request.incident_id:
                return ExecutionResult(
                    success=False, tool_name=request.tool_name, action=request.action, target=request.target,
                    execution_blocked=True, reason="incident_id_required",
                    error="Approved execution requires incident binding", approval_id=request.approval_id,
                )
            if not request.execution_capability:
                return ExecutionResult(
                    success=False, tool_name=request.tool_name, action=request.action, target=request.target,
                    execution_blocked=True, reason="execution_capability_required",
                    error="Approved execution requires a signed execution capability", approval_id=request.approval_id,
                )
            try:
                verify_execution_capability(
                    request.execution_capability,
                    incident_id=request.incident_id,
                    approval_id=request.approval_id,
                    tool_name=request.tool_name,
                    action=request.action,
                    target=request.target,
                    parameters=request.parameters,
                    timeout=request.timeout,
                    runbook_id=request.runbook_id,
                    runbook_version=request.runbook_version,
                    rollback=request.rollback,
                )
            except ExecutionCapabilityError as exc:
                logger.warning("execution_capability_rejected", reason=str(exc), approval_id=request.approval_id)
                return ExecutionResult(
                    success=False, tool_name=request.tool_name, action=request.action, target=request.target,
                    execution_blocked=True, reason="execution_capability_invalid", error=str(exc),
                    approval_id=request.approval_id,
                )

        tool_input = ToolInput(
            action=request.action,
            target=request.target,
            parameters=request.parameters,
            timeout=request.timeout,
            incident_id=request.incident_id,
            approval_id=request.approval_id,
            execution_capability=request.execution_capability,
            runbook_id=request.runbook_id,
            runbook_version=request.runbook_version,
            rollback=request.rollback,
        )

        validation = await tool.validate(tool_input)
        if not validation:
            return ExecutionResult(
                success=False, tool_name=request.tool_name, action=request.action, target=request.target,
                execution_blocked=True, reason="validation_failed", error="Tool input validation failed",
                approval_id=request.approval_id,
            )

        result = await tool_registry.execute_tool(
            tool_name=request.tool_name,
            input_data=tool_input,
            agent_name=request.agent_name,
        )

        return ExecutionResult(
            success=bool(result.get("success", False)),
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
