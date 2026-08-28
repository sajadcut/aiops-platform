"""Allowlisted execution-tool registry and second authorization boundary."""
from typing import Any, Dict, List, Optional

from apps.execution_service.capability import ExecutionCapabilityError, verify_execution_capability
from apps.execution_service.tools.base import BaseTool, ToolInput
from domain.contracts.logging import logger


class ToolRegistry:
    _instance: Optional["ToolRegistry"] = None
    _tools: Dict[str, BaseTool]

    def __new__(cls):
        if cls._instance is None:
            instance = super().__new__(cls)
            instance._tools = {}
            cls._instance = instance
        return cls._instance

    def register(self, tool: BaseTool) -> None:
        if tool.name in self._tools:
            logger.warning("execution_tool_overwritten", tool=tool.name)
        self._tools[tool.name] = tool
        logger.info("execution_tool_registered", tool=tool.name, risk_level=tool.risk_level, requires_approval=tool.requires_approval)

    def get_tool(self, name: str) -> Optional[BaseTool]:
        return self._tools.get(name)

    def list_tools(self, risk_level: Optional[str] = None) -> List[str]:
        tools = list(self._tools.values())
        if risk_level:
            tools = [tool for tool in tools if tool.risk_level == risk_level]
        return [tool.name for tool in tools]

    def get_allowed_tools(self, agent_name: str, risk_level: Optional[str] = None) -> List[str]:
        return self.list_tools(risk_level)

    async def validate_tool(self, tool_name: str, input_data: ToolInput) -> Dict[str, Any]:
        tool = self.get_tool(tool_name)
        if tool is None:
            return {"valid": False, "error": "tool_not_found"}
        try:
            valid = await tool.validate(input_data)
            return {"valid": bool(valid), "error": None if valid else "tool_validation_failed"}
        except Exception as exc:
            logger.exception("execution_tool_validation_exception", tool=tool_name, error_type=type(exc).__name__)
            return {"valid": False, "error": "tool_validation_exception"}

    @staticmethod
    def _verify_authorization(tool_name: str, tool: BaseTool, input_data: ToolInput) -> Optional[str]:
        if not tool.requires_approval:
            return None
        if not input_data.approval_id or not input_data.incident_id or not input_data.execution_capability:
            return "execution_capability_required"
        try:
            verify_execution_capability(
                input_data.execution_capability,
                incident_id=input_data.incident_id,
                approval_id=input_data.approval_id,
                tool_name=tool_name,
                action=input_data.action,
                target=input_data.target,
                parameters=input_data.parameters,
                timeout=input_data.timeout,
                runbook_id=input_data.runbook_id,
                runbook_version=input_data.runbook_version,
                rollback=input_data.rollback,
            )
        except ExecutionCapabilityError as exc:
            logger.warning("execution_registry_capability_rejected", tool=tool_name, approval_id=input_data.approval_id, reason=str(exc))
            return "execution_capability_invalid"
        return None

    async def execute_tool(self, tool_name: str, input_data: ToolInput, agent_name: str) -> Dict[str, Any]:
        tool = self.get_tool(tool_name)
        if tool is None:
            return {"success": False, "execution_blocked": True, "reason": "tool_not_found", "error": "tool_not_found"}

        authorization_error = self._verify_authorization(tool_name, tool, input_data)
        if authorization_error:
            return {
                "success": False,
                "execution_blocked": True,
                "reason": authorization_error,
                "tool": tool_name,
                "approval_id": input_data.approval_id,
            }

        validation = await self.validate_tool(tool_name, input_data)
        if not validation["valid"]:
            return {
                "success": False,
                "execution_blocked": True,
                "reason": "validation_failed",
                "error": validation["error"],
                "tool": tool_name,
            }

        try:
            logger.info("execution_tool_call_started", agent=agent_name, tool=tool_name, approval_id=input_data.approval_id)
            result = await tool.execute(input_data)
            response = result.model_dump()
            response.update({
                "tool": tool_name,
                "agent": agent_name,
                "risk_level": tool.risk_level,
                "requires_approval": tool.requires_approval,
                "approval_id": input_data.approval_id,
                "execution_blocked": False,
            })
            logger.info("execution_tool_call_completed", agent=agent_name, tool=tool_name, approval_id=input_data.approval_id, success=bool(response.get("success")))
            return response
        except Exception as exc:
            logger.exception("execution_tool_call_failed", tool=tool_name, agent=agent_name, approval_id=input_data.approval_id, error_type=type(exc).__name__)
            return {
                "success": False,
                "execution_blocked": False,
                "reason": "execution_failed",
                "error": "tool_execution_failed",
                "tool": tool_name,
                "agent": agent_name,
                "approval_id": input_data.approval_id,
            }

    def clear(self) -> None:
        self._tools.clear()


tool_registry = ToolRegistry()
