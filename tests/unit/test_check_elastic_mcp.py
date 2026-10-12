"""Offline regression tests for the Elastic MCP connectivity diagnostic."""
from __future__ import annotations

import asyncio
from io import StringIO

import httpx

from scripts.check_elastic_mcp import _http_status, check_connection


class FakeElasticClient:
    TOOL_EXECUTE_ESQL = "platform.core.execute_esql"
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
