# app/integrations/mcp_client.py
import httpx
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional
from domain.contracts.logging import logger

class MCPClient(ABC):
    def __init__(self, server_url: str, server_name: str):
        self.server_url = server_url
        self.server_name = server_name
        self._client = httpx.AsyncClient(timeout=30.0)

    async def _call_tool(self, tool_name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """ارسال درخواست به MCP Server با فرمت JSON-RPC"""
        payload = {
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {
                "name": tool_name,
                "arguments": arguments
            },
            "id": 1
        }
        try:
            response = await self._client.post(self.server_url, json=payload)
            response.raise_for_status()
            result = response.json()
            if "error" in result:
                logger.error(f"MCP error from {self.server_name}: {result['error']}")
                raise Exception(f"MCP error: {result['error']}")
            return result.get("result", {})
        except Exception as e:
            logger.error(f"Failed to call MCP tool {tool_name}: {str(e)}")
            raise

    async def list_tools(self) -> list:
        """دریافت لیست ابزارهای موجود از MCP Server"""
        payload = {
            "jsonrpc": "2.0",
            "method": "tools/list",
            "params": {},
            "id": 1
        }
        response = await self._client.post(self.server_url, json=payload)
        return response.json().get("result", {}).get("tools", [])