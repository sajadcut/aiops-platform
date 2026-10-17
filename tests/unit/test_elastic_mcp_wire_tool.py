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
        assert len(calls) == 5  # explicit, bounded alternative schema fields
        assert all(name == "platform_core_execute_esql" for name, _ in calls)
        assert all("FROM logs-*" in arguments["query"] for _, arguments in calls)
        for field in ("service.name", "service", "Properties.ServiceName.keyword",
                      "Properties.ServiceName", "service.name.keyword"):
            assert any(f"`{field}` ==" in arguments["query"] for _, arguments in calls)
        assert all("payment-api" in arguments["query"] for _, arguments in calls)
    finally:
        await client.close()


@pytest.mark.asyncio
async def test_discovery_finds_host_without_authorizing_vm(monkeypatch):
    client = ElasticsearchMCPClient()
    async def fake_tool(name, arguments):
        assert name == "platform_core_execute_esql"
        if "`service.name` ==" in arguments["query"]:
            return {"structuredContent": {"rows": [
                {"@timestamp": "2026-10-17T08:53:00Z", "service.name": "gfpapi",
                 "host.name": "app-01", "host.ip": ["10.0.0.10"], "message": "Redis timeout"},
                {"@timestamp": "2026-10-17T08:53:02Z", "service.name": "gfpapi",
                 "host.name": "app-01", "message": "Redis timeout"},
            ]}}
        return {"structuredContent": {"rows": []}}
    monkeypatch.setattr(client, "call_tool", fake_tool)
    try:
        candidates = await client.discover_service_hosts(
            "gfpapi", datetime(2026, 10, 17, 8, 30, tzinfo=timezone.utc))
        assert candidates["result_count"] == 2
        assert candidates["candidates"][0]["hostname"] == "app-01"
        assert candidates["candidates"][0]["record_count"] == 2
        assert candidates["candidates"][0]["status"] == "candidate"
        assert candidates["requires_independent_verification"] is True
    finally:
        await client.close()


@pytest.mark.asyncio
async def test_alias_lookup_is_opt_in_and_does_not_rename_service(monkeypatch):
    from domain.contracts.config import settings
    monkeypatch.setattr(settings, "ELASTIC_SERVICE_DISCOVERY_ALIASES",
                        {"gfpapi": ["GFP_Backend"]})
    client = ElasticsearchMCPClient()
    queries = []
    async def fake_tool(name, arguments):
        query = arguments["query"]
        queries.append(query)
        if "GFP_Backend" in query and "Properties.ServiceName.keyword" in query:
            return {"structuredContent": {"rows": [
                {"@timestamp": "2026-10-17T08:53:00Z", "Properties.ServiceName.keyword": "GFP_Backend",
                 "host.name": "app-02", "message": "redis failure"}
            ]}}
        return {"structuredContent": {"rows": []}}
    monkeypatch.setattr(client, "call_tool", fake_tool)
    try:
        logs = await client.get_logs("gfpapi", datetime.now(timezone.utc))
        assert len(logs) == 1
        assert logs[0].service == "GFP_Backend"
        assert any("GFP_Backend" in item for item in queries)
        assert len(queries) <= 10
    finally:
        await client.close()


@pytest.mark.asyncio
async def test_elastic_host_vm_verification_requires_allowlisted_exact_service(monkeypatch):
    from apps.signal_gateway import SignalGateway
    from domain.contracts.config import settings
    from integrations.vm import mcp_client as vm_module

    monkeypatch.setattr(settings, "SSH_ALLOWED_TARGETS", ["10.0.0.10"])
    monkeypatch.setattr(settings, "VM_MCP_URL", "http://vm.test/mcp")
    seen = []
    class FakeVM:
        async def service_status(self, target, service):
            seen.append((target, service))
            return {"success": True, "target": target, "service": service,
                    "active_state": "failed", "load_state": "loaded"}
        async def close(self):
            pass
    monkeypatch.setattr(vm_module, "VMEdgeMCPClient", FakeVM)
    discovery = {"status": "candidates_found", "candidates": [
        {"hostname": "app01", "ip_addresses": ["10.0.0.10"], "status": "candidate"}
    ]}
    evidence = await SignalGateway._verify_elastic_host_candidate("gfpapi", discovery)
    assert seen == [("10.0.0.10", "gfpapi")]
    assert discovery["status"] == "verified_by_vm_mcp"
    assert evidence[0]["raw_data"]["diagnostic"] == "service_status"
    assert evidence[0]["raw_data"]["target"] == "10.0.0.10"
    assert discovery["candidates"][0]["verification_status"] == "verified_read_only"


@pytest.mark.asyncio
async def test_elastic_host_vm_verification_rejects_unapproved_or_ambiguous_target(monkeypatch):
    from apps.signal_gateway import SignalGateway
    from domain.contracts.config import settings
    from integrations.vm import mcp_client as vm_module

    monkeypatch.setattr(settings, "SSH_ALLOWED_TARGETS", ["10.0.0.10"])
    monkeypatch.setattr(settings, "VM_MCP_URL", "http://vm.test/mcp")
    class ExplodingVM:
        def __init__(self):
            raise AssertionError("VM MCP must not be called for unsafe target")
    monkeypatch.setattr(vm_module, "VMEdgeMCPClient", ExplodingVM)
    for candidates in (
        [{"hostname": "app01", "ip_addresses": ["10.0.0.99"]}],
        [{"hostname": "a", "ip_addresses": ["10.0.0.10"]},
         {"hostname": "b", "ip_addresses": ["10.0.0.11"]}],
    ):
        discovery = {"status": "candidates_found", "candidates": candidates}
        assert await SignalGateway._verify_elastic_host_candidate("gfpapi", discovery) == []
        assert discovery["status"] == "candidates_found"


@pytest.mark.asyncio
async def test_elastic_host_vm_service_mismatch_must_not_bind(monkeypatch):
    from apps.signal_gateway import SignalGateway
    from domain.contracts.config import settings
    from integrations.vm import mcp_client as vm_module

    monkeypatch.setattr(settings, "SSH_ALLOWED_TARGETS", ["10.0.0.10"])
    monkeypatch.setattr(settings, "VM_MCP_URL", "http://vm.test/mcp")
    class FakeVM:
        async def service_status(self, target, service):
            return {"success": True, "target": target, "service": "nginx",
                    "active_state": "active", "load_state": "loaded"}
        async def close(self):
            pass
    monkeypatch.setattr(vm_module, "VMEdgeMCPClient", FakeVM)
    discovery = {"status": "candidates_found", "candidates": [
        {"hostname": "app01", "ip_addresses": ["10.0.0.10"]}
    ]}
    assert await SignalGateway._verify_elastic_host_candidate("gfpapi", discovery) == []
    assert discovery["status"] == "candidates_found"
    assert discovery["candidates"][0]["verification_status"] == "vm_service_identity_not_confirmed"
