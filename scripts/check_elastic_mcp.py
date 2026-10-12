"""Read-only Elastic Agent Builder MCP connectivity diagnostic for the AIOps runtime.

Run from the repository root (and preferably inside the running AIOps container):
    python -m scripts.check_elastic_mcp

Uses the same ElasticsearchMCPClient, configuration and authentication header
as incident evidence collection. Never prints credentials or server response bodies.
"""
from __future__ import annotations

import asyncio
import os
import sys
from typing import TextIO
from urllib.parse import parse_qs, urlsplit

import httpx

from domain.contracts.config import settings
from integrations.elasticsearch.mcp_client import ElasticsearchMCPClient


def _http_status(error: BaseException) -> int | None:
    """Recover the original HTTP status wrapped by MCPClient._post."""
    current: BaseException | None = error
    visited: set[int] = set()
    while current is not None and id(current) not in visited:
        visited.add(id(current))
        if isinstance(current, httpx.HTTPStatusError):
            return current.response.status_code
        current = current.__cause__ or current.__context__
    return None


def _safe_endpoint(url: str) -> tuple[str, str, str]:
    """Display the MCP target without URL userinfo or arbitrary query secrets."""
    parsed = urlsplit(url)
    hostname = parsed.hostname or "(unknown)"
    if ":" in hostname:
        hostname = f"[{hostname}]"
    port = f":{parsed.port}" if parsed.port is not None else ""
    endpoint = f"{parsed.scheme}://{hostname}{port}{parsed.path}"
    namespaces = ",".join(parse_qs(parsed.query).get("namespace", [])) or "(none)"
    return endpoint, namespaces, parsed.scheme


def _failure(stage: str, error: Exception, output: TextIO) -> int:
    status = _http_status(error)
    if status == 401:
        print(
            f"FAIL {stage}: HTTP 401 Unauthorized. Verify effective AIOps runtime "
            "credentials, Authorization header, and any proxy/auth provider.",
            file=output,
        )
        return 3
    if status == 403:
        print(
            f"FAIL {stage}: HTTP 403 Forbidden. Check Agent Builder Read privilege, "
            "the Kibana Space, and access policies.",
            file=output,
        )
        return 4
    if status is not None:
        print(f"FAIL {stage}: HTTP {status}. Review the Kibana MCP endpoint and server logs.", file=output)
    else:
        print(f"FAIL {stage}: {type(error).__name__} (no HTTP status). Check transport, protocol and service logs.", file=output)
    return 5


async def check_connection(client: ElasticsearchMCPClient, *, output: TextIO) -> int:
    """Exercise initialize and tools/list, without issuing ES|QL or write calls."""
    try:
        endpoint, namespaces, scheme = _safe_endpoint(client.server_url)
        authorization = client._headers(include_protocol=False).get("Authorization", "")
        auth_scheme = authorization.split(" ", 1)[0] if authorization else "(missing)"
        overridden = any(
            key in os.environ
            for key in (
                "ELASTICSEARCH_MCP_AUTH_HEADER",
                "ELASTICSEARCH_MCP_USERNAME",
                "ELASTICSEARCH_MCP_PASSWORD",
            )
        )
        print(f"Endpoint: {endpoint}", file=output)
        print(f"Namespaces: {namespaces}", file=output)
        print(f"Runtime username configured: {bool(settings.ELASTICSEARCH_MCP_USERNAME)}", file=output)
        print(f"Authentication scheme: {auth_scheme}", file=output)
        print(f"Credential environment override present: {overridden}", file=output)
        if scheme != "https":
            print("WARNING: HTTP is unencrypted; use verified HTTPS for production credentials.", file=output)
        if not authorization:
            print("FAIL configuration: no Authorization header in effective AIOps MCP client.", file=output)
            return 2

        stage = "initialize"
        try:
            await client.initialize()
            print("PASS initialize", file=output)
            stage = "tools/list"
            tools = await client.list_tools()
            print("PASS tools/list", file=output)
        except Exception as error:
            return _failure(stage, error, output)

        names = {tool.get("name") for tool in tools if isinstance(tool, dict)}
        expected = client.TOOL_EXECUTE_ESQL
        if expected not in names:
            print(f"FAIL required tool unavailable: {expected}", file=output)
            return 6
        print(f"PASS required tool available: {expected}", file=output)
        print("RESULT: Elastic MCP connectivity OK (read-only; no ES|QL executed).", file=output)
        return 0
    finally:
        await client.close()


def main() -> int:
    try:
        client = ElasticsearchMCPClient()
    except Exception as error:
        print(f"FAIL client configuration: {type(error).__name__}", file=sys.stderr)
        return 2
    return asyncio.run(check_connection(client, output=sys.stdout))


if __name__ == "__main__":
    raise SystemExit(main())
