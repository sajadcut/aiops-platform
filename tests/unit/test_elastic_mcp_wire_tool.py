"""Agent Builder MCP wire-name regression tests."""
from __future__ import annotations

from datetime import datetime, timezone

import pytest

from integrations.elasticsearch.mcp_client import ElasticsearchMCPClient


@pytest.mark.asyncio
async def test_elastic_mcp_wire_tool_allowlist_and_discovery(monkeypatch):
    client = ElasticsearchMCPClient()
    calls = []

    async def fake_request(method, params, *, tool_name=None):
        calls.append((method, tool_name, params))
        if method == "tools/list":
            # Real Kibana 9.3.2 tooling, including disallowed capabilities.
            return {"tools": [
                {"name": "platform_core_search"},
                {"name": "platform_core_execute_esql"},
                {"name": "observability_get_anomaly_detection_jobs"},
            ]}
        if method == "tools/call":
            return {"content": []}
        raise AssertionError(f"unexpected MCP method: {method}")

    monkeypatch.setattr(client, "_request", fake_request)
    try:
        assert client.allowed_tools == frozenset({"platform_core_execute_esql"})
        tools = await client.list_tools()
        assert [tool["name"] for tool in tools] == ["platform_core_execute_esql"]
        assert await client.health_check()
        result = await client.call_tool("platform_core_execute_esql", {"query": "FROM logs-* | LIMIT 1"})
        assert result == {"content": []}
        assert calls[-1][0:2] == ("tools/call", "platform_core_execute_esql")
        assert calls[-1][2]["name"] == "platform_core_execute_esql"
        with pytest.raises(PermissionError):
            await client.call_tool("platform_core_search", {"query": "forbidden"})
        with pytest.raises(PermissionError):
            await client.call_tool("observability_get_anomaly_detection_jobs", {})
    finally:
        await client.close()


@pytest.mark.asyncio
async def test_elastic_get_logs_calls_actual_esql_wire_tool(monkeypatch):
    client = ElasticsearchMCPClient()
    calls = []

    async def fake_call_tool(name, arguments):
        calls.append((name, arguments))
        return {"structuredContent": {"rows": []}}

    monkeypatch.setattr(client, "call_tool", fake_call_tool)
    try:
        logs = await client.get_logs("payment-api", datetime.now(timezone.utc), limit=1)
        assert logs == []
        assert len(calls) == 1
        assert calls[0][0] == "platform_core_execute_esql"
        assert "FROM logs-*" in calls[0][1]["query"]
        assert "payment-api" in calls[0][1]["query"]
    finally:
        await client.close()
