from typing import Dict, List, Optional, Any

from app.tools.base import BaseTool, ToolInput
from app.core.logging import logger


class ToolRegistry:
    """
    Central registry for all operational tools.

    Responsibilities:
    - Register approved tools
    - Discover tools
    - Validate tool input
    - Enforce tool-level risk policy
    - Enforce approval before execution
    - Execute the selected tool
    """

    _instance: Optional["ToolRegistry"] = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._tools = {}

        return cls._instance

    # ============================================================
    # Registration
    # ============================================================

    def register(self, tool: BaseTool) -> None:
        """
        Register an operational tool.
        """

        if tool.name in self._tools:
            logger.warning(
                f"Tool '{tool.name}' already registered. "
                "Overwriting existing registration."
            )

        self._tools[tool.name] = tool

        logger.info(
            f"Tool '{tool.name}' registered "
            f"(risk={tool.risk_level}, "
            f"requires_approval={tool.requires_approval})"
        )

    # ============================================================
    # Discovery
    # ============================================================

    def get_tool(
        self,
        name: str,
    ) -> Optional[BaseTool]:

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

        return [
            tool.name
            for tool in tools
        ]

    def get_allowed_tools(
        self,
        agent_name: str,
        risk_level: Optional[str] = None,
    ) -> List[str]:

        """
        Return tools available to an agent.

        Agent-specific authorization will be implemented later
        through a dedicated policy layer.

        For now, only registered tools are exposed.
        """

        return self.list_tools(
            risk_level=risk_level
        )

    # ============================================================
    # Validation
    # ============================================================

    async def validate_tool(
        self,
        tool_name: str,
        input_data: ToolInput,
    ) -> Dict[str, Any]:

        tool = self.get_tool(tool_name)

        if not tool:

            return {
                "valid": False,
                "error": (
                    f"Tool '{tool_name}' "
                    "not found in registry"
                ),
            }

        try:

            valid = await tool.validate(
                input_data
            )

            if not valid:

                return {
                    "valid": False,
                    "error": (
                        f"Tool '{tool_name}' "
                        "rejected the input"
                    ),
                }

            return {
                "valid": True,
                "error": None,
            }

        except Exception as exc:

            logger.error(
                f"Tool validation failed: "
                f"{tool_name}: {exc}"
            )

            return {
                "valid": False,
                "error": str(exc),
            }

    # ============================================================
    # Execution
    # ============================================================

    async def execute_tool(
        self,
        tool_name: str,
        input_data: ToolInput,
        agent_name: str,
        approval_granted: bool = False,
        approval_id: Optional[str] = None,
    ) -> Dict[str, Any]:

        """
        Execute a registered operational tool.

        SECURITY RULE:

        A tool that requires approval MUST NOT execute unless
        approval_granted=True.

        This check exists at the ToolRegistry boundary so that
        an Agent cannot bypass the Decision/Approval layer.
        """

        tool = self.get_tool(
            tool_name
        )

        # --------------------------------------------------------
        # Tool existence
        # --------------------------------------------------------

        if not tool:

            error_message = (
                f"Tool '{tool_name}' "
                "not found in registry"
            )

            logger.error(
                error_message
            )

            return {
                "success": False,
                "error": error_message,
                "execution_blocked": True,
                "reason": "tool_not_found",
            }

        # --------------------------------------------------------
        # Approval enforcement
        # --------------------------------------------------------

        if (
            tool.requires_approval
            and not approval_granted
        ):

            error_message = (
                f"Execution of tool "
                f"'{tool_name}' requires approval."
            )

            logger.warning(
                f"Execution blocked: "
                f"agent={agent_name}, "
                f"tool={tool_name}, "
                f"risk={tool.risk_level}"
            )

            return {
                "success": False,
                "error": error_message,
                "execution_blocked": True,
                "reason": "approval_required",
                "tool": tool_name,
                "risk_level": tool.risk_level,
                "requires_approval": True,
                "approval_id": approval_id,
            }

        # --------------------------------------------------------
        # Approval metadata
        # --------------------------------------------------------

        if (
            tool.requires_approval
            and approval_granted
        ):

            logger.info(
                f"Approved execution: "
                f"agent={agent_name}, "
                f"tool={tool_name}, "
                f"approval_id={approval_id}"
            )

        else:

            logger.info(
                f"Auto-approved low-risk execution: "
                f"agent={agent_name}, "
                f"tool={tool_name}"
            )

        # --------------------------------------------------------
        # Input validation
        # --------------------------------------------------------

        validation = await self.validate_tool(
            tool_name=tool_name,
            input_data=input_data,
        )

        if not validation["valid"]:

            logger.warning(
                f"Tool input validation failed: "
                f"{tool_name}"
            )

            return {
                "success": False,
                "error": validation["error"],
                "execution_blocked": True,
                "reason": "validation_failed",
                "tool": tool_name,
            }

        # --------------------------------------------------------
        # Actual execution
        # --------------------------------------------------------

        logger.info(
            f"Executing tool '{tool_name}' "
            f"for agent '{agent_name}'"
        )

        try:

            result = await tool.execute(
                input_data
            )

            response = result.model_dump()

            response.setdefault(
                "tool",
                tool_name,
            )

            response.setdefault(
                "agent",
                agent_name,
            )

            response.setdefault(
                "risk_level",
                tool.risk_level,
            )

            response.setdefault(
                "requires_approval",
                tool.requires_approval,
            )

            response.setdefault(
                "approval_id",
                approval_id,
            )

            response.setdefault(
                "execution_blocked",
                False,
            )

            return response

        except Exception as exc:

            logger.exception(
                f"Tool execution failed: "
                f"{tool_name}: {exc}"
            )

            return {
                "success": False,
                "error": str(exc),
                "execution_blocked": False,
                "reason": "execution_failed",
                "tool": tool_name,
                "agent": agent_name,
                "risk_level": tool.risk_level,
                "approval_id": approval_id,
            }

    # ============================================================
    # Registry state
    # ============================================================

    def clear(self) -> None:
        """
        Clear all registered tools.

        Primarily useful for tests.
        """

        self._tools.clear()

        logger.info(
            "Tool registry cleared."
        )


# ================================================================
# Global singleton
# ================================================================

tool_registry = ToolRegistry()