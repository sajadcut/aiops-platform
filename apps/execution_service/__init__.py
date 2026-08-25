# Controlled execution boundary for all operational tools.
from __future__ import annotations

from time import monotonic
from typing import Any, Dict, Optional

from pydantic import BaseModel, Field
from sqlalchemy import text

from apps.audit_service import AuditService
from apps.execution_service.tools.base import ToolInput
from apps.execution_service.tools.registry import tool_registry
from database import AsyncSessionLocal
from domain.contracts.logging import logger


class ExecutionRequest(BaseModel):
    tool_name: str
    action: str
    target: str
    parameters: Dict[str, Any] = Field(default_factory=dict)
    timeout: int = Field(default=30, ge=1, le=3600)
    agent_name: str = "execution_service"
    approval_granted: bool = False
    approval_id: Optional[str] = None
    incident_id: Optional[str] = None


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
    # Agents themselves are analysis components; only these service callers may cross
    # the operational write boundary.
    ALLOWED_CALLERS = frozenset({"api", "execution_service", "remediation_workflow", "verification", "runbook_executor"})

    @classmethod
    async def _persist_execution(cls, request: ExecutionRequest, result: ExecutionResult) -> None:
        if not request.incident_id:
            return
        async with AsyncSessionLocal() as db:
            await db.execute(
                text(
                    """
                    INSERT INTO execution_results
                        (incident_id, approval_id, tool_name, action, target, success,
                         execution_blocked, reason, result, error, execution_time)
                    VALUES
                        (:incident_id, :approval_id, :tool_name, :action, :target, :success,
                         :execution_blocked, :reason, CAST(:result AS jsonb), :error, :execution_time)
                    """
                ),
                {
                    "incident_id": request.incident_id,
                    "approval_id": request.approval_id,
                    "tool_name": request.tool_name,
                    "action": request.action,
                    "target": request.target,
                    "success": result.success,
                    "execution_blocked": result.execution_blocked,
                    "reason": result.reason,
                    "result": __import__("json").dumps(result.result or {}, default=str),
                    "error": result.error,
                    "execution_time": result.execution_time,
                },
            )
            await db.commit()

    @classmethod
    async def execute(cls, request: ExecutionRequest) -> ExecutionResult:
        logger.info(
            f"Execution request: tool={request.tool_name}, action={request.action}, target={request.target}, caller={request.agent_name}"
        )
        if request.agent_name not in cls.ALLOWED_CALLERS:
            result = ExecutionResult(
                success=False,
                tool_name=request.tool_name,
                action=request.action,
                target=request.target,
                execution_blocked=True,
                reason="execution_boundary_violation",
                error="Only approved execution service callers may invoke operational tools.",
                approval_id=request.approval_id,
            )
            await cls._persist_execution(request, result)
            return result

        tool = tool_registry.get_tool(request.tool_name)
        if tool is None:
            result = ExecutionResult(
                success=False,
                tool_name=request.tool_name,
                action=request.action,
                target=request.target,
                execution_blocked=True,
                reason="tool_not_found",
                error=f"Tool '{request.tool_name}' is not registered",
                approval_id=request.approval_id,
            )
            await cls._persist_execution(request, result)
            return result

        if tool.requires_approval and not request.approval_granted:
            result = ExecutionResult(
                success=False,
                tool_name=request.tool_name,
                action=request.action,
                target=request.target,
                execution_blocked=True,
                reason="approval_required",
                error=f"Tool '{request.tool_name}' requires approval",
                approval_id=request.approval_id,
            )
            await cls._persist_execution(request, result)
            return result

        tool_input = ToolInput(
            action=request.action,
            target=request.target,
            parameters=request.parameters,
            timeout=request.timeout,
        )
        validation = await tool.validate(tool_input)
        if not validation:
            result = ExecutionResult(
                success=False,
                tool_name=request.tool_name,
                action=request.action,
                target=request.target,
                execution_blocked=True,
                reason="validation_failed",
                error="Tool input validation failed",
                approval_id=request.approval_id,
            )
            await cls._persist_execution(request, result)
            return result

        started = monotonic()
        AuditService.record(
            "tool_call_started",
            request.agent_name,
            request.incident_id,
            request.action,
            "started",
            {"tool_name": request.tool_name, "target": request.target, "approval_id": request.approval_id},
        )
        # Critical fix: propagate the approval decision into the registry boundary.
        raw = await tool_registry.execute_tool(
            tool_name=request.tool_name,
            input_data=tool_input,
            agent_name=request.agent_name,
            approval_granted=request.approval_granted,
            approval_id=request.approval_id,
        )
        elapsed = monotonic() - started

        result = ExecutionResult(
            success=bool(raw.get("success", False)),
            tool_name=request.tool_name,
            action=request.action,
            target=request.target,
            execution_blocked=bool(raw.get("execution_blocked", False)),
            reason=raw.get("reason"),
            result=raw.get("result"),
            error=raw.get("error"),
            execution_time=raw.get("execution_time") if raw.get("execution_time") is not None else elapsed,
            approval_id=request.approval_id,
        )
        AuditService.record(
            "tool_call_completed",
            request.agent_name,
            request.incident_id,
            request.action,
            "success" if result.success else "failed",
            {
                "tool_name": request.tool_name,
                "target": request.target,
                "approval_id": request.approval_id,
                "execution_blocked": result.execution_blocked,
                "error": result.error,
            },
        )
        await cls._persist_execution(request, result)
        return result