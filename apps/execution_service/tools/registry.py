"""Registry مرکزی ابزارهایی که اجازه عبور از execution boundary را دارند."""

from typing import Dict, List, Optional, Any

from apps.execution_service.tools.base import BaseTool, ToolInput
from domain.contracts.logging import logger


class ToolRegistry:
    """ابزارهای شناخته‌شده را نگه می‌دارد و اجرای unknown/unapproved را fail-closed می‌کند."""

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
            logger.warning("tool_registry_overwrite", tool=tool.name)
        self._tools[tool.name] = tool
        logger.info(
            "tool_registered",
            tool=tool.name,
            risk_level=tool.risk_level,
            requires_approval=tool.requires_approval,
        )

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
            logger.exception("tool_validation_exception", tool=tool_name, error_type=type(exc).__name__)
            return {"valid": False, "error": "tool_validation_failed"}

    async def execute_tool(
        self,
        tool_name: str,
        input_data: ToolInput,
        agent_name: str,
        approval_granted: bool = False,
        approval_id: Optional[str] = None,
        execution_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        tool = self.get_tool(tool_name)
        if tool is None:
            return {
                "success": False,
                "execution_blocked": True,
                "reason": "tool_not_found",
                "error": "requested tool is not registered",
            }

        if tool.requires_approval and not approval_granted:
            logger.warning(
                "execution_blocked_approval_required",
                execution_id=execution_id,
                tool=tool_name,
                approval_id=approval_id,
                agent=agent_name,
            )
            return {
                "success": False,
                "execution_blocked": True,
                "reason": "approval_required",
                "tool": tool_name,
                "approval_id": approval_id,
            }

        validation = await self.validate_tool(tool_name, input_data)
        if not validation["valid"]:
            return {
                "success": False,
                "execution_blocked": True,
                "reason": "validation_failed",
                "error": "tool input validation failed",
                "tool": tool_name,
            }

        try:
            logger.info(
                "tool_execution_started",
                execution_id=execution_id,
                tool=tool_name,
                action=input_data.action,
                target=input_data.target,
                agent=agent_name,
                approval_id=approval_id,
            )
            result = await tool.execute(input_data)
            response = result.model_dump()
            response.update(
                {
                    "tool": tool_name,
                    "agent": agent_name,
                    "risk_level": tool.risk_level,
                    "requires_approval": tool.requires_approval,
                    "approval_id": approval_id,
                    "execution_id": execution_id,
                    "execution_blocked": False,
                }
            )
            logger.info(
                "tool_execution_completed",
                execution_id=execution_id,
                tool=tool_name,
                action=input_data.action,
                target=input_data.target,
                agent=agent_name,
                approval_id=approval_id,
                success=bool(response.get("success")),
            )
            return response
        except Exception as exc:
            logger.exception(
                "tool_execution_failed",
                execution_id=execution_id,
                tool=tool_name,
                action=input_data.action,
                target=input_data.target,
                agent=agent_name,
                approval_id=approval_id,
                error_type=type(exc).__name__,
            )
            return {
                "success": False,
                "execution_blocked": False,
                "reason": "execution_failed",
                "error": "tool execution failed",
                "tool": tool_name,
                "agent": agent_name,
                "approval_id": approval_id,
                "execution_id": execution_id,
            }

    def clear(self) -> None:
        self._tools.clear()


tool_registry = ToolRegistry()
