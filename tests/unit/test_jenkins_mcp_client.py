import asyncio

import pytest

from integrations.jenkins.mcp_client import JenkinsMCPClient
from integrations.mcp_client import MCPClient


READ_AUTH = "Basic dGVzdDp0b2tlbg=="
WRITE_AUTH = "Basic d3JpdGU6dG9rZW4="
URL = "https://jenkins.example/mcp-server/mcp"


def _client(**kwargs) -> JenkinsMCPClient:
    return JenkinsMCPClient(
        URL,
        authorization_header=kwargs.pop("authorization_header", READ_AUTH),
        write_authorization_header=kwargs.pop("write_authorization_header", None),
        expected_identity=kwargs.pop("expected_identity", "aiops-reader"),
        origin=kwargs.pop("origin", "https://jenkins.example"),
        enable_writes=kwargs.pop("enable_writes", False),
        **kwargs,
    )


def test_official_jenkins_mcp_contract_uses_streamable_http_and_2025_06_18():
    client = _client()
    try:
        assert client.server_url == URL
        assert client.protocol_version == "2025-06-18"
        assert client.health_url == "https://jenkins.example/mcp-health"
        assert "getJob" in client.allowed_tools
        assert "getBuildLog" in client.allowed_tools
        assert "whoAmI" in client.allowed_tools
        assert "getStatus" in client.allowed_tools
        assert "triggerBuild" not in client.allowed_tools
        assert not client.write_tools
    finally:
        asyncio.run(client.close())


def test_jenkins_headers_use_basic_auth_and_optional_origin():
    client = _client()
    try:
        headers = client._headers()
        assert headers["Authorization"] == READ_AUTH
        assert headers["Origin"] == "https://jenkins.example"
        assert headers["MCP-Protocol-Version"] == "2025-06-18"
    finally:
        asyncio.run(client.close())


def test_write_tools_are_disabled_by_default_and_direct_write_call_is_forbidden():
    client = _client()
    try:
        with pytest.raises(PermissionError, match="jenkins_write_requires_governed_method"):
            asyncio.run(client.call_tool("triggerBuild", {"jobFullName": "payments/build"}))
        with pytest.raises(PermissionError, match="jenkins_mcp_writes_disabled"):
            asyncio.run(
                client.trigger_build(
                    "payments/build",
                    approval_id="approval-1",
                    incident_id="incident-1",
                    execution_capability="capability-1",
                )
            )
    finally:
        asyncio.run(client.close())


def test_enabling_writes_requires_separate_write_identity():
    with pytest.raises(ValueError, match="jenkins_mcp_write_auth_header_required"):
        _client(enable_writes=True)


def test_governed_trigger_build_uses_official_tool_shape_and_write_identity(monkeypatch):
    calls = []

    async def fake_call_tool(self, tool_name, arguments):
        calls.append((tool_name, arguments, self._authorization(tool_name)))
        return {"content": [{"type": "text", "text": "{\"id\": 42}"}]}

    monkeypatch.setattr(MCPClient, "call_tool", fake_call_tool)
    client = _client(enable_writes=True, write_authorization_header=WRITE_AUTH)
    try:
        result = asyncio.run(
            client.trigger_build(
                "payments/build",
                parameters={"BRANCH": "main", "DEBUG_MODE": False},
                approval_id="approval-1",
                incident_id="incident-1",
                execution_capability="capability-1",
            )
        )
        assert result == {"id": 42}
        assert calls == [
            (
                "triggerBuild",
                {"jobFullName": "payments/build", "parameters": {"BRANCH": "main", "DEBUG_MODE": False}},
                WRITE_AUTH,
            )
        ]
    finally:
        asyncio.run(client.close())


def test_write_wrapper_requires_governance_context(monkeypatch):
    async def fake_call_tool(self, tool_name, arguments):
        return {"content": []}

    monkeypatch.setattr(MCPClient, "call_tool", fake_call_tool)
    client = _client(enable_writes=True, write_authorization_header=WRITE_AUTH)
    try:
        with pytest.raises(PermissionError, match="jenkins_write_approval_id_required"):
            asyncio.run(
                client.rebuild_build(
                    "payments/build",
                    approval_id="",
                    incident_id="incident-1",
                    execution_capability="capability-1",
                )
            )
    finally:
        asyncio.run(client.close())


def test_read_wrappers_bound_upstream_pagination_and_log_search(monkeypatch):
    calls = []

    async def fake_call_tool(self, tool_name, arguments):
        calls.append((tool_name, arguments))
        return {"content": [{"type": "text", "text": "[]"}]}

    monkeypatch.setattr(MCPClient, "call_tool", fake_call_tool)
    client = _client()
    try:
        asyncio.run(client.get_jobs("team", skip=-5, limit=999))
        asyncio.run(
            client.search_build_log(
                "payments/build",
                "ERROR",
                build_number=7,
                use_regex=False,
                ignore_case=True,
                max_matches=9999,
                context_lines=99,
            )
        )
        assert calls[0] == ("getJobs", {"skip": 0, "limit": 10, "parentFullName": "team"})
        assert calls[1] == (
            "searchBuildLog",
            {
                "jobFullName": "payments/build",
                "pattern": "ERROR",
                "useRegex": False,
                "ignoreCase": True,
                "maxMatches": 200,
                "contextLines": 5,
                "buildNumber": 7,
            },
        )
    finally:
        asyncio.run(client.close())


def test_health_check_fails_closed_on_anonymous_or_identity_mismatch(monkeypatch):
    client = _client(expected_identity="aiops-reader")

    async def healthy():
        return {"httpStatus": 200, "mcpServerStatus": "ok", "shuttingDown": False}

    async def anonymous():
        return {"fullName": "anonymous"}

    async def wrong_identity():
        return {"fullName": "different-user"}

    async def expected_identity():
        return {"fullName": "aiops-reader"}

    try:
        monkeypatch.setattr(client, "mcp_health", healthy)
        monkeypatch.setattr(client, "who_am_i", anonymous)
        assert asyncio.run(client.health_check()) is False

        monkeypatch.setattr(client, "who_am_i", wrong_identity)
        assert asyncio.run(client.health_check()) is False

        monkeypatch.setattr(client, "who_am_i", expected_identity)
        assert asyncio.run(client.health_check()) is True
    finally:
        asyncio.run(client.close())
