# ============================================================
# FILE: app/tools/registry.py
# ============================================================

from typing import Dict, List, Optional, Any

from app.tools.base import BaseTool, ToolInput
from app.core.logging import logger


class ToolRegistry:
    """Central registry and controlled execution boundary."""

    _instance: Optional["ToolRegistry"] = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._tools = {}
        return cls._instance

    def register(self, tool: BaseTool) -> None:
        if tool.name in self._tools:
            logger.warning(
                f"Tool '{tool.name}' already registered, overwriting"
            )

        self._tools[tool.name] = tool

        logger.info(
            f"Tool '{tool.name}' registered "
            f"(risk={tool.risk_level}, "
            f"requires_approval={tool.requires_approval})"
        )

    def get_tool(self, name: str) -> Optional[BaseTool]:
        return self._tools.get(name)

    def list_tools(
        self,
        risk_level: Optional[str] = None,
    ) -> List[str]:

        tools = list(self._tools.values())

        if risk_level:
            tools = [
                tool
                for tool in tools
                if tool.risk_level == risk_level
            ]

        return [tool.name for tool in tools]

    def get_allowed_tools(
        self,
        agent_name: str,
        risk_level: Optional[str] = None,
    ) -> List[str]:

        return self.list_tools(risk_level)

    async def validate_tool(
        self,
        tool_name: str,
        input_data: ToolInput,
    ) -> Dict[str, Any]:

        tool = self.get_tool(tool_name)

        if tool is None:
            return {
                "valid": False,
                "error": f"Tool '{tool_name}' not found",
            }

        try:
            valid = await tool.validate(input_data)

            return {
                "valid": bool(valid),
                "error": None if valid else "Tool validation failed",
            }

        except Exception as exc:
            logger.exception(
                f"Validation failed for tool '{tool_name}'"
            )

            return {
                "valid": False,
                "error": str(exc),
            }

    async def execute_tool(
        self,
        tool_name: str,
        input_data: ToolInput,
        agent_name: str,
        approval_granted: bool = False,
        approval_id: Optional[str] = None,
    ) -> Dict[str, Any]:

        tool = self.get_tool(tool_name)

        if tool is None:
            return {
                "success": False,
                "execution_blocked": True,
                "reason": "tool_not_found",
                "error": f"Tool '{tool_name}' not found",
            }

        if tool.requires_approval and not approval_granted:
            logger.warning(
                f"Execution blocked for '{tool_name}': "
                f"approval required"
            )

            return {
                "success": False,
                "execution_blocked": True,
                "reason": "approval_required",
                "tool": tool_name,
                "approval_id": approval_id,
            }

        validation = await self.validate_tool(
            tool_name,
            input_data,
        )

        if not validation["valid"]:
            return {
                "success": False,
                "execution_blocked": True,
                "reason": "validation_failed",
                "error": validation["error"],
                "tool": tool_name,
            }

        try:
            logger.info(
                f"Agent '{agent_name}' executing "
                f"tool '{tool_name}'"
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
                    "execution_blocked": False,
                }
            )

            return response

        except Exception as exc:
            logger.exception(
                f"Tool '{tool_name}' execution failed"
            )

            return {
                "success": False,
                "execution_blocked": False,
                "reason": "execution_failed",
                "error": str(exc),
                "tool": tool_name,
                "agent": agent_name,
                "approval_id": approval_id,
            }

    def clear(self) -> None:
        self._tools.clear()


tool_registry = ToolRegistry()