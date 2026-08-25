"""Legacy MCP-like JSON-RPC compatibility client.

This module predates the current MCP authorization specification and is NOT a
canonical production transport. Active operational evidence collection uses the
governed native connector layer.

Do not use this client for Production or privileged tools: it does not implement
OAuth 2.1 Protected Resource Metadata, RFC 8707 resource/audience binding,
step-up scopes, workload identity/mTLS, or capability-policy enforcement.

A future governed MCP adapter, if adopted, must be introduced by ADR and must
preserve the platform's Tool Registry / Policy / Approval / Audit boundaries.
"""
from __future__ import annotations

import warnings
from abc import ABC
from typing import Any, Dict

import httpx

from domain.contracts.logging import logger


class MCPClient(ABC):
    """Deprecated compatibility client; never an authorization boundary."""

    production_supported = False

    def __init__(self, server_url: str, server_name: str):
        warnings.warn(
            "integrations.MCPClient is a legacy non-production transport; use the governed connector/tool layer",
            DeprecationWarning,
            stacklevel=2,
        )
        self.server_url = server_url
        self.server_name = server_name
        self._client = httpx.AsyncClient(timeout=30.0)

    async def _call_tool(self, tool_name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        payload = {
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {"name": tool_name, "arguments": arguments},
            "id": 1,
        }
        try:
            response = await self._client.post(self.server_url, json=payload)
            response.raise_for_status()
            result = response.json()
            if "error" in result:
                logger.error(f"Legacy MCP error from {self.server_name}: {result['error']}")
                raise RuntimeError(f"Legacy MCP error: {result['error']}")
            return result.get("result", {})
        except Exception as exc:
            logger.error(f"Failed to call legacy MCP tool {tool_name}: {exc}")
            raise

    async def list_tools(self) -> list:
        payload = {"jsonrpc": "2.0", "method": "tools/list", "params": {}, "id": 1}
        response = await self._client.post(self.server_url, json=payload)
        response.raise_for_status()
        result = response.json()
        if "error" in result:
            raise RuntimeError(f"Legacy MCP error: {result['error']}")
        return result.get("result", {}).get("tools", [])

    async def close(self) -> None:
        await self._client.aclose()
