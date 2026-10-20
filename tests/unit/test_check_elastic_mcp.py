"""Offline regression tests for the Elastic MCP connectivity diagnostic."""
from __future__ import annotations

import asyncio
from io import StringIO

import httpx

from scripts.check_elastic_mcp import _http_status, check_connection


class FakeElasticClient:
    TOOL_EXECUTE_ESQL = "platform_core_execute_esql"
    server_url = "http://user:secret@kibana.local:5601/api/agent_builder/mcp?namespace=platform.core&secret=hidden"

    def __init__(self, *, authorization="Basic NOT_A_REAL_SECRET", fail_stage=None, status=None, tools=None):
        self.authorization = authorization
        self.fail_stage = fail_stage
        self.status = status
        self.tools = tools if tools is not None else [{"name": self.TOOL_EXECUTE_ESQL}]
        self.closed = False

    def _headers(self, *, include_protocol=True):
        return {"Authorization": self.authorization} if self.authorization else {}

    def _raise_if_requested(self, stage):
        if self.fail_stage == stage:
            request = httpx.Request("POST", "http://kibana.local/api/agent_builder/mcp")
            response = httpx.Response(self.status, request=request)
            cause = httpx.HTTPStatusError("HTTP request failed", request=request, response=response)
            raise RuntimeError("mcp_http_error:elastic-agent-builder") from cause

    async def initialize(self):
        self._raise_if_requested("initialize")
        return {"protocolVersion": "2024-11-05"}

    async def list_tools(self):
        self._raise_if_requested("tools/list")
        return self.tools

    async def close(self):
        self.closed = True


def run_check(client):
    output = StringIO()
    code = asyncio.run(check_connection(client, output=output))
    return code, output.getvalue()


def test_successful_initialize_and_tool_discovery():
    client = FakeElasticClient()
    code, output = run_check(client)
    assert code == 0
    assert "PASS initialize" in output
    assert "PASS tools/list" in output
    assert "PASS required tool available" in output
    assert client.closed
    assert "NOT_A_REAL_SECRET" not in output
    assert "user:secret" not in output
    assert "hidden" not in output


def test_missing_authentication_is_reported_without_network_call():
    client = FakeElasticClient(authorization="")
    code, output = run_check(client)
    assert code == 2
    assert "no Authorization header" in output
    assert client.closed


def test_wrapped_401_is_distinguished_from_403():
    client = FakeElasticClient(fail_stage="initialize", status=401)
    code, output = run_check(client)
    assert code == 3
    assert "HTTP 401 Unauthorized" in output
    assert client.closed


def test_wrapped_403_is_reported_as_permissions_issue():
    client = FakeElasticClient(fail_stage="initialize", status=403)
    code, output = run_check(client)
    assert code == 4
    assert "HTTP 403 Forbidden" in output
    assert client.closed


def test_tools_list_failure_preserves_stage_and_http_status():
    client = FakeElasticClient(fail_stage="tools/list", status=403)
    code, output = run_check(client)
    assert code == 4
    assert "PASS initialize" in output
    assert "FAIL tools/list: HTTP 403" in output
    assert client.closed


def test_missing_allowlisted_tool_is_not_a_pass():
    client = FakeElasticClient(tools=[])
    code, output = run_check(client)
    assert code == 6
    assert "FAIL required tool unavailable" in output
    assert client.closed


def test_http_status_not_in_unrelated_errors():
    assert _http_status(RuntimeError("offline")) is None

def test_dotted_logical_tool_name_does_not_pass_wire_discovery():
    client = FakeElasticClient(tools=[{"name": "platform.core.execute_esql"}])
    code, output = run_check(client)
    assert code == 6
    assert "platform_core_execute_esql" in output
    assert client.closed


import pytest
from integrations.mcp_client import MCPClient


def _expired_session_error():
    request = httpx.Request("POST", "https://mcp.example.test/mcp")
    response = httpx.Response(404, request=request)
    try:
        raise httpx.HTTPStatusError("MCP session expired", request=request, response=response)
    except httpx.HTTPStatusError as cause:
        raise RuntimeError("mcp_http_error:prometheus") from cause


@pytest.mark.asyncio
async def test_mcp_expired_session_read_reinitializes_only_once(monkeypatch):
    client = MCPClient(
        "https://mcp.example.test/mcp", "prometheus",
        allowed_tools={"ready", "dangerous"}, write_tools={"dangerous"},
    )
    client._initialized = True
    client.session_id = "stale-session"
    calls = []

    async def fake_post(payload, **kwargs):
        calls.append((payload["method"], client.session_id))
        if payload["method"] == "tools/call" and client.session_id == "stale-session":
            _expired_session_error()
        if payload["method"] == "initialize":
            client.session_id = "fresh-session"
            return {"result": {"protocolVersion": "2025-03-26"}}
        if payload["method"] == "notifications/initialized":
            return {}
        return {"result": {"content": [{"type": "text", "text": "ready"}]}}
    monkeypatch.setattr(client, "_post", fake_post)
    try:
        result = await client.call_tool("ready", {})
        assert result["content"][0]["text"] == "ready"
        assert [method for method, _ in calls] == [
            "tools/call", "initialize", "notifications/initialized", "tools/call",
        ]
        assert calls[0][1] == "stale-session"
        assert calls[-1][1] == "fresh-session"
    finally:
        client.session_id = None
        await client.close()


@pytest.mark.asyncio
async def test_mcp_expired_session_does_not_replay_write_or_single_attempt_read(monkeypatch):
    client = MCPClient(
        "https://mcp.example.test/mcp", "prometheus",
        allowed_tools={"ready", "dangerous"}, write_tools={"dangerous"},
    )
    client._initialized = True
    client.session_id = "stale-session"
    client.single_attempt_read_tools = frozenset({"ready"})
    calls = []
    async def fake_post(payload, **kwargs):
        calls.append(payload["method"])
        _expired_session_error()
    monkeypatch.setattr(client, "_post", fake_post)
    try:
        with pytest.raises(RuntimeError, match="mcp_http_error:prometheus"):
            await client.call_tool("dangerous", {})
        with pytest.raises(RuntimeError, match="mcp_http_error:prometheus"):
            await client.call_tool("ready", {})
        assert calls == ["tools/call", "tools/call"]
        assert client.session_id == "stale-session"
    finally:
        client.session_id = None
        await client.close()
