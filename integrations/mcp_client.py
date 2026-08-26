"""Governed MCP Streamable-HTTP client used by all external integrations.

The AIOps Control Plane does not call external operational systems directly.
Zabbix, Elasticsearch, Prometheus, Kubernetes and VM/Edge capabilities are
reached through an MCP Server deployed in the corresponding trust zone.

MCP is a transport/capability boundary, not an authorization authority. Write
operations must still pass Tool Registry -> Policy -> Approval -> Execution ->
Audit. Agents never receive a raw MCP client.
"""
from __future__ import annotations

import itertools
from typing import Any, Dict, Iterable, Optional
from urllib.parse import urlparse

import httpx

from domain.contracts.logging import logger


class MCPClient:
    """Governed remote MCP client for stateless Streamable HTTP.

    Tool names are allowlisted client-side. Optional write tools use a distinct
    bearer identity so compromise of read-only Evidence credentials cannot
    authorize mutation capabilities.
    """

    production_supported = True
    _ids = itertools.count(1)

    def __init__(
        self,
        server_url: str,
        server_name: str,
        *,
        allowed_tools: Iterable[str],
        write_tools: Iterable[str] = (),
        protocol_version: str = "2026-07-28",
        timeout: float = 30.0,
        bearer_token: Optional[str] = None,
        write_bearer_token: Optional[str] = None,
        ca_cert_path: Optional[str] = None,
        client_cert_path: Optional[str] = None,
        client_key_path: Optional[str] = None,
        require_https: bool = True,
    ):
        self.server_url = str(server_url or "").strip()
        self.server_name = server_name
        self.allowed_tools = frozenset(str(x) for x in allowed_tools)
        self.write_tools = frozenset(str(x) for x in write_tools)
        if not self.write_tools <= self.allowed_tools:
            raise ValueError("mcp_write_tools_must_be_allowlisted")
        self.protocol_version = protocol_version
        self.timeout = float(timeout)
        self.bearer_token = bearer_token
        self.write_bearer_token = write_bearer_token
        self.require_https = bool(require_https)

        parsed = urlparse(self.server_url)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise ValueError(f"invalid_mcp_server_url:{server_name}")
        if self.require_https and parsed.scheme != "https":
            raise ValueError(f"mcp_https_required:{server_name}")
        if bool(client_cert_path) != bool(client_key_path):
            raise ValueError("mcp_client_cert_and_key_must_be_configured_together")

        verify: bool | str = ca_cert_path or True
        cert = (client_cert_path, client_key_path) if client_cert_path and client_key_path else None
        self._client = httpx.AsyncClient(timeout=self.timeout, verify=verify, cert=cert)

    def _headers(self, method: str, name: Optional[str] = None) -> Dict[str, str]:
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
            "Mcp-Protocol-Version": self.protocol_version,
            "Mcp-Method": method,
        }
        if name:
            headers["Mcp-Name"] = name
        token = self.write_bearer_token if name in self.write_tools else self.bearer_token
        if name in self.write_tools and not token:
            raise PermissionError(f"mcp_write_identity_required:{self.server_name}:{name}")
        if token:
            headers["Authorization"] = f"Bearer {token}"
        return headers

    async def _request(self, method: str, params: Dict[str, Any], *, name: Optional[str] = None) -> Dict[str, Any]:
        payload = {"jsonrpc": "2.0", "method": method, "params": params, "id": next(self._ids)}
        try:
            response = await self._client.post(self.server_url, json=payload, headers=self._headers(method, name))
            response.raise_for_status()
            result = response.json()
        except PermissionError:
            raise
        except Exception as exc:
            logger.error("MCP request failed server=%s method=%s: %s", self.server_name, method, exc)
            raise RuntimeError(f"mcp_transport_error:{self.server_name}") from exc
        if result.get("error"):
            raise RuntimeError(f"mcp_remote_error:{self.server_name}:{result['error']}")
        return result.get("result", {})

    async def call_tool(self, tool_name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        if tool_name not in self.allowed_tools:
            raise PermissionError(f"mcp_tool_not_allowed:{self.server_name}:{tool_name}")
        return await self._request("tools/call", {"name": tool_name, "arguments": arguments}, name=tool_name)

    async def _call_tool(self, tool_name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        return await self.call_tool(tool_name, arguments)

    async def list_tools(self) -> list:
        result = await self._request("tools/list", {})
        tools = result.get("tools", [])
        return [tool for tool in tools if isinstance(tool, dict) and tool.get("name") in self.allowed_tools]

    async def health_check(self) -> bool:
        try:
            await self.list_tools()
            return True
        except Exception:
            return False

    async def close(self) -> None:
        await self._client.aclose()
