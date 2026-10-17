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


@pytest.mark.asyncio
async def test_elastic_hostname_only_probe_uses_exact_allowlisted_hostname(monkeypatch):
    """No host.ip in Elastic -> connect by host.name, read only."""
    from apps.signal_gateway import SignalGateway
    from domain.contracts.config import settings
    from integrations.vm import mcp_client as vm_module

    hostname = "GFP-App01.internal.example"
    monkeypatch.setattr(settings, "SSH_ALLOWED_TARGETS", [hostname])
    monkeypatch.setattr(settings, "VM_MCP_URL", "http://vm.test/mcp")
    invoked = []

    class FakeVM:
        async def service_status(self, target, service):
            invoked.append((target, service))
            return {
                "success": True, "service": service, "target": target,
                "active_state": "active", "load_state": "loaded",
            }

        async def close(self):
            pass

    monkeypatch.setattr(vm_module, "VMEdgeMCPClient", FakeVM)
    discovery = {"status": "candidates_found", "candidates": [{
        "hostname": hostname.lower(), "ip_addresses": [],
        "record_count": 2,
    }]}
    observations = await SignalGateway._verify_elastic_host_candidate("gfpapi", discovery)
    assert invoked == [(hostname, "gfpapi")]
    assert discovery["status"] == "verified_by_vm_mcp"
    assert discovery["verified_target"] == hostname
    assert discovery["candidates"][0]["verification_method"] == "hostname"
    assert discovery["candidates"][0]["verification_status"] == "verified_read_only"
    assert observations[0]["source"] == "vm_mcp"
    assert observations[0]["raw_data"]["target"] == hostname


@pytest.mark.asyncio
async def test_elastic_hostname_without_ip_must_not_bypass_allowlist(monkeypatch):
    """A log entry is never permission to probe an arbitrary hostname."""
    from apps.signal_gateway import SignalGateway
    from domain.contracts.config import settings
    from integrations.vm import mcp_client as vm_module

    monkeypatch.setattr(settings, "SSH_ALLOWED_TARGETS", ["10.0.0.10"])
    monkeypatch.setattr(settings, "VM_MCP_URL", "http://vm.test/mcp")

    class UnexpectedVM:
        def __init__(self):
            raise AssertionError("unapproved hostname must never reach VM MCP")

    monkeypatch.setattr(vm_module, "VMEdgeMCPClient", UnexpectedVM)
    discovery = {"status": "candidates_found", "candidates": [{
        "hostname": "app01.internal.example", "ip_addresses": [],
    }]}
    result = await SignalGateway._verify_elastic_host_candidate("gfpapi", discovery)
    assert result == []
    assert discovery["candidates"][0]["verification_method"] == "hostname"
    assert discovery["candidates"][0]["verification_status"] == "candidate_hostname_not_allowlisted"
    assert "verified_target" not in discovery


@pytest.mark.asyncio
async def test_elastic_hostname_only_invalid_or_unreachable_stays_unverified(monkeypatch):
    from apps.signal_gateway import SignalGateway
    from domain.contracts.config import settings
    from integrations.vm import mcp_client as vm_module

    monkeypatch.setattr(settings, "VM_MCP_URL", "http://vm.test/mcp")
    monkeypatch.setattr(settings, "SSH_ALLOWED_TARGETS", ["app01.internal.example"])

    class UnreachableVM:
        async def service_status(self, target, service):
            raise OSError("test connection refused")

        async def close(self):
            pass

    monkeypatch.setattr(vm_module, "VMEdgeMCPClient", UnreachableVM)
    unreachable = {"status": "candidates_found", "candidates": [{
        "hostname": "app01.internal.example", "ip_addresses": [],
    }]}
    assert await SignalGateway._verify_elastic_host_candidate("gfpapi", unreachable) == []
    assert unreachable["candidates"][0]["verification_status"] == "vm_read_failed"
    assert unreachable["candidates"][0]["verification_method"] == "hostname"

    invalid = {"status": "candidates_found", "candidates": [{
        "hostname": "../server;rm -rf", "ip_addresses": [],
    }]}
    assert await SignalGateway._verify_elastic_host_candidate("gfpapi", invalid) == []
    assert invalid["candidates"][0]["verification_status"] == "candidate_hostname_invalid"


@pytest.mark.asyncio
async def test_elastic_host_discovery_retains_hostname_when_ip_missing(monkeypatch):
    client = ElasticsearchMCPClient()

    async def fake_call_tool(name, arguments):
        assert name == "platform_core_execute_esql"
        # Simulate an ECS index with host.name but no mapped host.ip.
        if "`host.ip`" in arguments["query"]:
            raise ValueError("unknown column host.ip")
        return {"structuredContent": {"rows": [{
            "@timestamp": "2026-10-17T10:30:00Z",
            "service.name": "gfpapi",
            "host.name": "app01.internal.example",
        }]}}

    monkeypatch.setattr(client, "call_tool", fake_call_tool)
    try:
        discovered = await client.discover_service_hosts(
            "gfpapi", datetime(2026, 10, 17, 10, 15, tzinfo=timezone.utc))
        assert discovered["status"] == "candidates_found"
        assert discovered["candidates"][0]["hostname"] == "app01.internal.example"
        assert discovered["candidates"][0]["ip_addresses"] == []
    finally:
        await client.close()


def test_elastic_decodes_nested_esql_table_formats():
    parser = ElasticsearchMCPClient._rows_from_payload
    assert parser({"result": {"data": {
        "columns": [{"name": "host.name"}, {"name": "service.name"}],
        "values": [["gfp-host-01", "GFP_Backend"]]
    }}}) == [{"host.name": "gfp-host-01", "service.name": "GFP_Backend"}]
    assert parser({"results": [{"data": {
        "columns": ["host.name"], "rows": [["gfp-host-02"]]
    }}]}) == [{"host.name": "gfp-host-02"}]
    assert parser({"rows": []}) == []


@pytest.mark.asyncio
async def test_configured_gfp_index_and_space_do_not_change_esql_tool_namespace(monkeypatch):
    from domain.contracts.config import settings
    monkeypatch.setattr(settings, "ELASTIC_AGENT_BUILDER_INDEX_PATTERN",
                        "1m-digitaloperation-gfpapi-*")
    monkeypatch.setattr(settings, "ELASTIC_AGENT_BUILDER_MCP_NAMESPACES",
                        ["platform.core"])
    client = ElasticsearchMCPClient(
        server_url="http://kibana.test/s/mcp/api/agent_builder/mcp")
    calls = []

    async def fake_tool(name, arguments):
        assert name == "platform_core_execute_esql"
        calls.append(arguments["query"])
        return {"structuredContent": {"rows": [{
            "@timestamp": "2026-10-17T10:15:00Z", "host.name": "gfp-host-01",
            "service.name": "GFP_Backend",
        }]}}
    monkeypatch.setattr(client, "call_tool", fake_tool)
    try:
        assert "/s/mcp/api/agent_builder/mcp" in client.server_url
        assert "namespace=platform.core" in client.server_url
        hosts = await client.discover_service_hosts(
            "GFP_Backend", datetime(2026, 10, 17, 10, 0, tzinfo=timezone.utc))
        assert calls
        assert all(query.startswith("FROM 1m-digitaloperation-gfpapi-* | WHERE ")
                   for query in calls)
        assert hosts["status"] == "candidates_found"
        assert hosts["index_pattern"] == "1m-digitaloperation-gfpapi-*"
        assert hosts["candidates"][0]["hostname"] == "gfp-host-01"
    finally:
        await client.close()


@pytest.mark.asyncio
async def test_index_probe_distinguishes_wrong_service_filter_from_empty_index(monkeypatch):
    from domain.contracts.config import settings
    monkeypatch.setattr(settings, "ELASTIC_AGENT_BUILDER_INDEX_PATTERN",
                        "1m-digitaloperation-gfpapi-*")
    client = ElasticsearchMCPClient()
    seen = []

    async def fake_tool(name, arguments):
        query = arguments["query"]
        seen.append(query)
        if query.endswith("| LIMIT 1"):
            return {"structuredContent": {"result": {
                "columns": ["@timestamp", "service.name"],
                "values": [["2026-10-17T10:15:00Z", "gfpapi"]]
            }}}
        return {"structuredContent": {"rows": []}}
    monkeypatch.setattr(client, "call_tool", fake_tool)
    try:
        report = await client.discover_service_hosts(
            "GFP_Backend", datetime(2026, 10, 17, 10, 0, tzinfo=timezone.utc))
        assert report["status"] == "index_has_rows_no_service_time_match"
        assert report["index_probe"] == "has_rows"
        assert report["candidates"] == []  # never bind host from index-only query
        assert seen[-1] == "FROM 1m-digitaloperation-gfpapi-* | LIMIT 1"
    finally:
        await client.close()
