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


def test_esql_empty_table_is_decoded_from_json_string_content_block():
    client = ElasticsearchMCPClient()
    response = {
        "structuredContent": {"task_id": "metadata-only"},
        "content": [
            {"type": "text", "text": '{"columns":[{"name":"@timestamp"}],"values":[]}'}
        ],
    }
    selected = client._esql_payloads(response)
    assert len(selected) == 1
    assert client._esql_empty_table(selected[0]) is True
    assert client._rows_from_payload(selected[0]) == []


def test_esql_unknown_metadata_does_not_claim_zero_rows():
    client = ElasticsearchMCPClient()
    unknown = {"structuredContent": {"task_id": "metadata-only"},
               "content": [{"type": "text", "text": "query accepted"}]}
    selected = client._esql_payloads(unknown)
    assert len(selected) == 1
    assert client._esql_empty_table(selected[0]) is False
    assert client._rows_from_payload(selected[0]) == []


@pytest.mark.asyncio
async def test_empty_esql_text_envelopes_are_not_unrecognized(monkeypatch):
    client = ElasticsearchMCPClient()
    async def fake_call_tool(name, arguments):
        return {"structuredContent": {"status": "completed"},
                "content": [{"type": "text", "text": '{"rows":[]}'}]}
    monkeypatch.setattr(client, "call_tool", fake_call_tool)
    try:
        result = await client.get_logs(
            "gfpapi", datetime(2026, 10, 19, 17, 0, tzinfo=timezone.utc),
            limit=20,
        )
        assert result == []
        diagnostics = client._last_esql_query_diagnostics
        assert diagnostics["success_count"] == 5
        assert diagnostics["unrecognized_envelopes"] == 0
        assert diagnostics["recognized_empty_envelopes"] == 5
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
        assert report["sample_field_names"] == ["@timestamp", "service.name"]
        assert report["candidates"] == []  # never bind host from index-only query
        assert seen[-1] == "FROM 1m-digitaloperation-gfpapi-* | LIMIT 1"
    finally:
        await client.close()


def test_elastic_future_window_covers_clock_skew_but_is_bounded(monkeypatch):
    from datetime import timedelta
    from apps.signal_gateway import SignalGateway
    from domain.contracts.config import settings
    monkeypatch.setattr(settings, "ELASTIC_ANOMALY_CONTEXT_LOOKAHEAD_SECONDS", 300)
    now = datetime(2026, 10, 17, 10, 15, tzinfo=timezone.utc)
    ahead = now + timedelta(seconds=273)
    since, until, meta = SignalGateway._elastic_discovery_window(ahead, now)
    assert since == now - timedelta(minutes=20)
    assert ahead < until <= now + timedelta(minutes=5)
    assert meta["timestamp_skew_seconds"] == 273
    assert meta["time_window_status"] == "future_skew_included"
    late = now - timedelta(hours=1)
    prior, end, _ = SignalGateway._elastic_discovery_window(late, now)
    assert prior == late - timedelta(minutes=20)
    assert end == now
    _, capped, extreme_meta = SignalGateway._elastic_discovery_window(
        now + timedelta(days=5), now)
    assert capped == now + timedelta(minutes=5)
    assert extreme_meta["time_window_status"] == "future_skew_capped"


@pytest.mark.asyncio
async def test_elastic_host_ip_only_is_discovered_when_host_name_unmapped(monkeypatch):
    client = ElasticsearchMCPClient()
    queries = []
    async def fake_tool(name, arguments):
        query = arguments["query"]
        queries.append(query)
        if chr(96) + "host.name" + chr(96) in query:
            raise ValueError("missing host.name mapping")
        if chr(96) + "host.ip" + chr(96) in query:
            return {"structuredContent": {"rows": [{
                "@timestamp": "2026-10-17T10:15:00Z",
                "service.name": "gfpapi", "host.ip": "10.0.0.10"
            }]}}
        return {"structuredContent": {"rows": []}}
    monkeypatch.setattr(client, "call_tool", fake_tool)
    try:
        report = await client.discover_service_hosts(
            "gfpapi", datetime(2026, 10, 17, 10, 0, tzinfo=timezone.utc))
        assert report["status"] == "candidates_found"
        assert report["candidates"][0]["hostname"] == "10.0.0.10"
        assert report["candidates"][0]["ip_addresses"] == ["10.0.0.10"]
        assert any(chr(96) + "host.ip" + chr(96) in query
                   and chr(96) + "host.name" + chr(96) not in query for query in queries)
    finally:
        await client.close()


@pytest.mark.asyncio
async def test_explicit_reverse_elastic_alias_gets_used_in_esql(monkeypatch):
    from domain.contracts.config import settings
    monkeypatch.setattr(settings, "ELASTIC_SERVICE_DISCOVERY_ALIASES",
                        {"gfpapi": ["GFP_Backend"]})
    client = ElasticsearchMCPClient()
    queries = []
    async def fake_tool(name, arguments):
        query = arguments["query"]
        queries.append(query)
        if '"gfpapi"' in query:
            return {"structuredContent": {"rows": [{
                "@timestamp": "2026-10-17T10:15:00Z",
                "service.name": "gfpapi", "host.name": "app-1"
            }]}}
        return {"structuredContent": {"rows": []}}
    monkeypatch.setattr(client, "call_tool", fake_tool)
    try:
        logs = await client.get_logs(
            "GFP_Backend", datetime(2026, 10, 17, 10, 0, tzinfo=timezone.utc))
        assert len(logs) == 1
        assert logs[0].service == "gfpapi"
        assert any('"gfpapi"' in query for query in queries)
    finally:
        await client.close()


@pytest.mark.asyncio
async def test_verified_runtime_alias_requires_exact_vm_evidence_and_config(monkeypatch):
    from apps.signal_gateway import SignalGateway
    from apps.context_service.service_identity import ServiceIdentityResolver
    from apps.incident_copilot import vm_binding
    from apps.incident_vm_identity import vm_binding_diagnostic
    from domain.contracts.config import settings
    from integrations.vm import mcp_client as vm_module

    monkeypatch.setattr(settings, "VM_MCP_URL", "http://vm.test/mcp")
    monkeypatch.setattr(settings, "SSH_ALLOWED_TARGETS", ["gfp-app.internal"])
    monkeypatch.setattr(settings, "ELASTIC_SERVICE_DISCOVERY_ALIASES",
                        {"gfpapi": ["GFP_Backend"]})
    seen = []
    class FakeVM:
        async def service_status(self, target, service):
            seen.append((target, service))
            if service != "gfpapi":
                return {"success": False, "target": target, "service": service}
            return {"success": True, "target": target, "service": service,
                    "load_state": "loaded", "active_state": "failed"}
        async def close(self):
            pass

    monkeypatch.setattr(vm_module, "VMEdgeMCPClient", FakeVM)
    discovery = {"status": "candidates_found", "candidates": [{
        "hostname": "gfp-app.internal", "ip_addresses": [],
    }]}
    evidence = await SignalGateway._verify_elastic_host_candidate("GFP_Backend", discovery)
    assert seen == [("gfp-app.internal", "gfpapi")]
    assert discovery["status"] == "verified_by_vm_mcp"
    assert discovery["verified_runtime_service"] == "gfpapi"
    assert discovery["reported_log_service"] == "GFP_Backend"
    assert evidence[0]["raw_data"]["service"] == "gfpapi"
    assert evidence[0]["raw_data"]["source_service_label"] == "GFP_Backend"

    association = {"source_service": "GFP_Backend", "runtime_service": "gfpapi",
                   "target": "gfp-app.internal",
                   "evidence_reference": evidence[0]["reference"],
                   "verification": "vm_mcp_service_status"}
    context = {"verified_runtime_mapping": association,
               "service_identity": {"service": "gfpapi", "status": "verified"},
               "trigger_signal": {"service": "GFP_Backend"}}
    assert ServiceIdentityResolver.verified_runtime_alias_matches(
        "GFP_Backend", "gfpapi", context, evidence)
    assert vm_binding_diagnostic("gfpapi", evidence, context)["candidate"] == "gfp-app.internal"
    assert vm_binding("gfpapi", evidence, context)["target"] == "gfp-app.internal"

    wrong = [{"source": "vm_mcp", "reference": evidence[0]["reference"],
              "raw_data": {**evidence[0]["raw_data"], "service": "nginx"}}]
    assert not ServiceIdentityResolver.verified_runtime_alias_matches(
        "GFP_Backend", "gfpapi", context, wrong)
    assert not ServiceIdentityResolver.verified_runtime_alias_matches(
        "GFP_Backend", "gfpapi", context, [])
    assert vm_binding("gfpapi", wrong, context) is None
    monkeypatch.setattr(settings, "ELASTIC_SERVICE_DISCOVERY_ALIASES", {})
    assert not ServiceIdentityResolver.verified_runtime_alias_matches(
        "GFP_Backend", "gfpapi", context, evidence)
    assert vm_binding("gfpapi", evidence, context) is None


def test_ambiguous_reverse_runtime_alias_does_not_guess(monkeypatch):
    from apps.signal_gateway import SignalGateway
    from domain.contracts.config import settings
    monkeypatch.setattr(settings, "ELASTIC_SERVICE_DISCOVERY_ALIASES",
                        {"service-a": ["GFP_Backend"], "service-b": ["GFP_Backend"]})
    assert SignalGateway._runtime_service_candidates("GFP_Backend") == ["GFP_Backend"]


@pytest.mark.asyncio
async def test_ingest_host_discovery_promotes_runtime_name_only_after_vm_proof(monkeypatch):
    from datetime import timedelta
    from apps.signal_gateway import SignalGateway, OperationalSignal
    from apps.rag_service import KnowledgeRAGService
    from domain.contracts.config import settings
    from integrations.elasticsearch import mcp_client as elastic_module
    from integrations.vm import mcp_client as vm_module

    monkeypatch.setattr(settings, "VM_MCP_URL", "http://vm.test/mcp")
    monkeypatch.setattr(settings, "SSH_ALLOWED_TARGETS", ["gfp-app.internal"])
    monkeypatch.setattr(settings, "ELASTIC_SERVICE_DISCOVERY_ALIASES",
                        {"gfpapi": ["GFP_Backend"]})
    monkeypatch.setattr(settings, "ELASTIC_ANOMALY_CONTEXT_LOOKAHEAD_SECONDS", 300)

    async def no_knowledge(self, *args, **kwargs):
        return []
    monkeypatch.setattr(KnowledgeRAGService, "search", no_knowledge)
    query_windows = []
    class FakeElastic:
        async def discover_service_hosts(self, service, since, until):
            query_windows.append((service, since, until))
            return {"status": "candidates_found", "searched_service": service,
                    "candidates": [{"hostname": "gfp-app.internal", "ip_addresses": []}],
                    "result_count": 1}
        async def close(self):
            pass
    class FakeVM:
        async def service_status(self, target, service):
            if service == "gfpapi":
                return {"success": True, "target": target, "service": service,
                        "load_state": "loaded", "active_state": "failed"}
            return {"success": False, "target": target, "service": service}
        async def close(self):
            pass
    monkeypatch.setattr(elastic_module, "ElasticsearchMCPClient", FakeElastic)
    monkeypatch.setattr(vm_module, "VMEdgeMCPClient", FakeVM)
    now = datetime.now(timezone.utc)
    signal = OperationalSignal(
        source="elasticsearch", source_id="ingest-alias-proof-1",
        signal_type="redis_error_threshold", summary="Redis errors elevated",
        service="GFP_Backend", timestamp=now + timedelta(seconds=273))
    result = await SignalGateway._knowledge_assisted_asset(signal, signal.to_evidence())
    assert result["service_identity"]["service"] == "gfpapi"
    assert result["service_identity"]["status"] == "verified"
    assert result["service_identity"]["reported_service"] == "GFP_Backend"
    assert result["asset_context"]["service"] == "gfpapi"
    assert result["verified_runtime_mapping"]["source_service"] == "GFP_Backend"
    assert result["verified_runtime_mapping"]["runtime_service"] == "gfpapi"
    assert result["host_discovery"]["mapping_status"] == "verified_runtime_promoted"
    assert result["host_discovery"]["timestamp_skew_seconds"] >= 270
    assert query_windows[0][0] == "GFP_Backend"
    assert query_windows[0][2] > now


def test_nested_empty_esql_table_is_not_schema_error():
    checker = ElasticsearchMCPClient._esql_empty_table
    assert checker({"results": [{"data": {
        "columns": [{"name": "host.name"}], "values": []
    }}]})
    assert checker({"result": {"data": {"columns": ["x"], "rows": []}}})
    assert not checker({"result": {"message": "unexpected envelope"}})
    assert not checker({"results": ["raw text"]})


@pytest.mark.asyncio
async def test_serilog_schema_retry_finds_machine_name_in_gfp_index(monkeypatch):
    from domain.contracts.config import settings
    monkeypatch.setattr(settings, "ELASTIC_AGENT_BUILDER_INDEX_PATTERN",
                        "1m-digitaloperation-gfpapi-*")
    monkeypatch.setattr(settings, "ELASTIC_SERVICE_DISCOVERY_ALIASES",
                        {"gfpapi": ["GFP_Backend"]})
    client = ElasticsearchMCPClient()
    queries = []

    async def fake_tool(name, arguments):
        assert name == "platform_core_execute_esql"
        query = arguments["query"]
        queries.append(query)
        if query.endswith("| LIMIT 1"):
            return {"structuredContent": {"columns": [
                {"name": "@timestamp"}, {"name": "Timestamp"},
                {"name": "Properties.ServiceName"},
                {"name": "Properties.ServiceName.keyword"},
                {"name": "Properties.MachineName"},
            ], "values": [["2026-10-17T11:00:00Z",
                           "2026-10-17T11:00:00Z", "gfpapi", "gfpapi",
                           "gfp-app.internal"]]}}
        if ("Properties.ServiceName" in query and "GFP_Backend" in query
                and "Properties.MachineName" in query):
            return {"structuredContent": {"rows": [{
                "@timestamp": "2026-10-17T11:00:00Z",
                "Properties.ServiceName.keyword": "GFP_Backend",
                "Properties.MachineName": "gfp-app.internal",
            }]}}
        if ("Properties.ServiceName" in query and "gfpapi" in query
                and "Properties.MachineName" in query):
            return {"structuredContent": {"rows": [{
                "@timestamp": "2026-10-17T11:00:00Z",
                "Properties.ServiceName.keyword": "gfpapi",
                "Properties.MachineName": "gfp-app.internal",
            }]}}
        # Elastic returned a result envelope, but the old ECS-only query
        # could not decode it as a table.
        return {"structuredContent": {"details": {"status": "unrecognized"}}}

    monkeypatch.setattr(client, "call_tool", fake_tool)
    try:
        result = await client.discover_service_hosts(
            "GFP_Backend", datetime(2026, 10, 17, 10, 45, tzinfo=timezone.utc),
            datetime(2026, 10, 17, 11, 5, tzinfo=timezone.utc))
        assert result["status"] == "candidates_found"
        assert result["index_probe"] == "has_rows"
        assert result["observed_schema_lookup"] is True
        assert result["candidates"][0]["hostname"] == "gfp-app.internal"
        assert result["result_count"] >= 1
        assert any("Properties.MachineName" in query and "Properties.ServiceName" in query
                   and "WHERE " in query for query in queries)
        assert all("FROM 1m-digitaloperation-gfpapi-*" in query for query in queries)
    finally:
        await client.close()


@pytest.mark.asyncio
async def test_unparseable_esql_is_not_false_service_time_mismatch(monkeypatch):
    from domain.contracts.config import settings
    monkeypatch.setattr(settings, "ELASTIC_SERVICE_DISCOVERY_ALIASES", {})
    client = ElasticsearchMCPClient()

    async def fake_tool(name, arguments):
        if arguments["query"].endswith("| LIMIT 1"):
            return {"structuredContent": {"rows": [{
                "@timestamp": "2026-10-17T11:00:00Z",
                "Properties.ServiceName": "gfpapi",
                "Properties.MachineName": "gfp-app.internal",
            }]}}
        return {"structuredContent": {"error": "unexpected backend format"}}

    monkeypatch.setattr(client, "call_tool", fake_tool)
    try:
        result = await client.discover_service_hosts(
            "gfpapi", datetime(2026, 10, 17, 10, 45, tzinfo=timezone.utc))
        assert result["status"] == "response_format_unrecognized"
        assert result["candidates"] == []
        assert result["unrecognized_envelopes"] >= 1
        assert result["index_probe"] == "has_rows"
    finally:
        await client.close()


@pytest.mark.asyncio
async def test_old_gfp_redis_logs_are_searched_historically_with_live_vm_proof(monkeypatch):
    from datetime import timedelta
    from apps.signal_gateway import SignalGateway, OperationalSignal
    from apps.rag_service import KnowledgeRAGService
    from domain.contracts.config import settings
    from integrations.elasticsearch import mcp_client as elastic_module
    from integrations.vm import mcp_client as vm_module

    monkeypatch.setattr(settings, "ELASTIC_SERVICE_DISCOVERY_ALIASES",
                        {"gfpapi": ["GFP_Backend"]})
    monkeypatch.setattr(settings, "SSH_ALLOWED_TARGETS", ["10.248.16.82"])
    monkeypatch.setattr(settings, "VM_MCP_URL", "http://vm.test/mcp")

    async def knowledge_empty(self, *args, **kwargs):
        return []
    monkeypatch.setattr(KnowledgeRAGService, "search", knowledge_empty)
    intervals = []
    probes = []

    class ElasticWithDelayedLogs:
        async def discover_service_hosts(self, service, since, until):
            intervals.append((service, since, until))
            if since >= datetime.now(timezone.utc) - timedelta(hours=1):
                return {"status": "index_has_rows_no_service_time_match",
                        "searched_service": service, "result_count": 0,
                        "candidates": []}
            return {"status": "candidates_found", "searched_service": service,
                    "result_count": 6, "candidates": [{
                        "hostname": "apgfpdtnksa0101",
                        "ip_addresses": ["10.248.16.82"], "record_count": 6
                    }]}
        async def close(self):
            pass

    class VerifyingVM:
        async def service_status(self, target, service):
            probes.append((target, service))
            if service != "gfpapi":
                return {"success": False, "target": target, "service": service}
            return {"success": True, "target": target, "service": service,
                    "load_state": "loaded", "active_state": "active"}
        async def close(self):
            pass

    monkeypatch.setattr(elastic_module, "ElasticsearchMCPClient", ElasticWithDelayedLogs)
    monkeypatch.setattr(vm_module, "VMEdgeMCPClient", VerifyingVM)
    signal = OperationalSignal(
        source="elasticsearch", source_id="redis-delayed-host-001",
        signal_type="redis_error_threshold", summary="Redis Connection refused",
        service="GFP_Backend", timestamp=datetime.now(timezone.utc))
    resolution = await SignalGateway._knowledge_assisted_asset(
        signal, signal.to_evidence())
    history = resolution["host_discovery"]
    assert len(intervals) == 2
    assert intervals[0][1] > intervals[1][1]
    assert intervals[1][1] <= datetime.now(timezone.utc) - timedelta(hours=5)
    assert history["search_strategy"] == "bounded_historical"
    assert history["recent_lookup_status"] == "index_has_rows_no_service_time_match"
    assert history["historical_candidate_requires_live_verification"] is True
    assert history["verified_target"] == "10.248.16.82"
    assert history["verified_runtime_service"] == "gfpapi"
    assert probes == [("10.248.16.82", "gfpapi")]
    assert resolution["verified_runtime_mapping"]["runtime_service"] == "gfpapi"


def test_elastic_parses_json_text_result_without_trusting_metadata_only_envelope():
    import json
    client = ElasticsearchMCPClient()
    payload = {"columns": [{"name": "host.name"}, {"name": "host.ip"}],
               "values": [["apgfpdtnksa0101", "10.248.16.82"]]}
    wrapped = {"structuredContent": {"status": "success"},
               "content": [{"type": "text", "text": json.dumps(payload)}]}
    assert client._esql_payloads(wrapped) == wrapped["content"]
    assert client._rows_from_payload(wrapped["content"][0]) == [{
        "host.name": "apgfpdtnksa0101", "host.ip": "10.248.16.82"
    }]
    assert client._rows_from_payload({"result": json.dumps(payload)}) == [{
        "host.name": "apgfpdtnksa0101", "host.ip": "10.248.16.82"
    }]


@pytest.mark.asyncio
async def test_gfp_serilog_keeps_host_ip_and_verifies_allowlisted_ip_not_unlisted_hostname(monkeypatch):
    """Regression for Kibana evidence: host.name is not allowlisted but host.ip is."""
    from apps.signal_gateway import SignalGateway
    from domain.contracts.config import settings
    from integrations.vm import mcp_client as vm_module

    monkeypatch.setattr(settings, "ELASTIC_AGENT_BUILDER_INDEX_PATTERN",
                        "1m-digitaloperation-gfpapi-*")
    monkeypatch.setattr(settings, "ELASTIC_SERVICE_DISCOVERY_ALIASES",
                        {"gfpapi": ["GFP_Backend"]})
    monkeypatch.setattr(settings, "SSH_ALLOWED_TARGETS", ["10.248.16.82"])
    monkeypatch.setattr(settings, "VM_MCP_URL", "http://vm.test/mcp")
    client = ElasticsearchMCPClient()
    seen_queries = []
    async def fake_tool(name, arguments):
        query = arguments["query"]
        seen_queries.append(query)
        if query.endswith("| LIMIT 1"):
            return {"structuredContent": {"rows": [{
                "@timestamp": "2026-10-17T11:10:00Z",
                "Properties.ServiceName.keyword": "GFP_Backend",
                "Properties.MachineName": "apgfpdtnksa0101",
                "host.name": "apgfpdtnksa0101", "host.ip": "10.248.16.82",
            }]}}
        if ("Properties.MachineName" in query and "host.ip" in query
                and "Properties.ServiceName" in query):
            return {"structuredContent": {"rows": [{
                "@timestamp": "2026-10-17T11:10:00Z",
                "Properties.ServiceName.keyword": "GFP_Backend",
                "Properties.MachineName": "apgfpdtnksa0101",
                "host.name": "apgfpdtnksa0101", "host.ip": "10.248.16.82",
            }]}}
        return {"structuredContent": {"rows": []}}
    monkeypatch.setattr(client, "call_tool", fake_tool)
    try:
        discovery = await client.discover_service_hosts(
            "GFP_Backend", datetime(2026, 10, 17, 11, 0, tzinfo=timezone.utc),
            datetime(2026, 10, 17, 11, 15, tzinfo=timezone.utc))
        assert discovery["status"] == "candidates_found"
        assert discovery["candidates"] == [{
            "hostname": "apgfpdtnksa0101",
            "ip_addresses": ["10.248.16.82"], "source": "elasticsearch",
            "status": "candidate", "record_count": 1
        }]
        assert any("host.ip" in query and "host.name" in query
                   and "Properties.MachineName" in query for query in seen_queries)
    finally:
        await client.close()

    seen_statuses = []
    class FakeVM:
        async def service_status(self, target, service):
            seen_statuses.append((target, service))
            return {"success": service == "gfpapi", "target": target,
                    "service": service, "load_state": (
                        "loaded" if service == "gfpapi" else "not-found"),
                    "active_state": ("active" if service == "gfpapi" else "inactive")}
        async def close(self):
            pass

    monkeypatch.setattr(vm_module, "VMEdgeMCPClient", FakeVM)
    evidence = await SignalGateway._verify_elastic_host_candidate("GFP_Backend", discovery)
    assert evidence
    assert discovery["candidates"][0]["verification_method"] == "ip"
    assert discovery["verified_target"] == "10.248.16.82"
    assert seen_statuses == [("10.248.16.82", "gfpapi")]
    assert discovery["verified_runtime_service"] == "gfpapi"


@pytest.mark.asyncio
async def test_api_process_allowlist_missing_even_when_vm_worker_config_is_correct(monkeypatch):
    """No VM MCP call when this API process did not load its target policy."""
    from apps.signal_gateway import SignalGateway
    from domain.contracts.config import settings
    from integrations.vm import mcp_client as vm_module

    monkeypatch.setattr(settings, "VM_MCP_URL", "http://vm.test/mcp")
    monkeypatch.setattr(settings, "SSH_ALLOWED_TARGETS", [])
    class UnexpectedVM:
        def __init__(self):
            raise AssertionError("API must reject before sending worker probe")
    monkeypatch.setattr(vm_module, "VMEdgeMCPClient", UnexpectedVM)
    discovery = {"status": "candidates_found", "candidates": [{
        "hostname": "apgfpdtnksa0101", "ip_addresses": ["10.248.16.82"],
    }]}
    assert await SignalGateway._verify_elastic_host_candidate(
        "gfpapi", discovery) == []
    candidate = discovery["candidates"][0]
    assert candidate["verification_status"] == "candidate_ip_not_allowlisted"
    assert candidate["control_plane_target_allowed"] is False
    assert candidate["control_plane_allowlist_count"] == 0


@pytest.mark.asyncio
async def test_allowlisted_hostname_selected_if_ip_is_not_authorized(monkeypatch):
    """Hostnames are not skipped simply because an unallowlisted IP exists."""
    from apps.signal_gateway import SignalGateway
    from domain.contracts.config import settings
    from integrations.vm import mcp_client as vm_module

    monkeypatch.setattr(settings, "VM_MCP_URL", "http://vm.test/mcp")
    monkeypatch.setattr(settings, "SSH_ALLOWED_TARGETS", ["apgfpdtnksa0101"])
    seen = []
    class FakeVM:
        async def service_status(self, target, service):
            seen.append((target, service))
            return {"success": True, "target": target, "service": service,
                    "load_state": "loaded", "active_state": "active"}
        async def close(self):
            pass
    monkeypatch.setattr(vm_module, "VMEdgeMCPClient", FakeVM)
    discovery = {"status": "candidates_found", "candidates": [{
        "hostname": "apgfpdtnksa0101", "ip_addresses": ["10.248.16.82"],
    }]}
    evidence = await SignalGateway._verify_elastic_host_candidate(
        "gfpapi", discovery)
    assert evidence
    assert seen == [("apgfpdtnksa0101", "gfpapi")]
    assert discovery["verified_target"] == "apgfpdtnksa0101"
    assert discovery["candidates"][0]["verification_method"] == "hostname"
    assert discovery["candidates"][0]["control_plane_allowlist_count"] == 1
    assert discovery["candidates"][0]["control_plane_target_allowed"] is True


@pytest.mark.asyncio
@pytest.mark.parametrize("policy_error,code", [
    ("vm_target_not_allowed", "vm_worker_target_not_allowlisted"),
    ("vm_service_not_allowed", "vm_worker_service_not_allowlisted"),
])
async def test_vm_worker_policy_denial_is_not_misreported_as_ssh_failure(
        monkeypatch, policy_error, code):
    from apps.signal_gateway import SignalGateway
    from domain.contracts.config import settings
    from integrations.vm import mcp_client as vm_module

    monkeypatch.setattr(settings, "VM_MCP_URL", "http://vm.test/mcp")
    monkeypatch.setattr(settings, "SSH_ALLOWED_TARGETS", ["10.248.16.82"])
    class RejectingVM:
        async def service_status(self, target, service):
            raise PermissionError(policy_error)
        async def close(self):
            pass
    monkeypatch.setattr(vm_module, "VMEdgeMCPClient", RejectingVM)
    discovery = {"status": "candidates_found", "candidates": [{
        "hostname": "apgfpdtnksa0101", "ip_addresses": ["10.248.16.82"],
    }]}
    assert await SignalGateway._verify_elastic_host_candidate(
        "gfpapi", discovery) == []
    assert discovery["candidates"][0]["verification_status"] == code
    assert discovery["candidates"][0]["control_plane_target_allowed"] is True
    assert discovery["runtime_probe_count"] == 1


@pytest.mark.asyncio
async def test_elastic_vm_refuses_reported_alias_when_systemd_id_is_different(monkeypatch):
    from apps.signal_gateway import SignalGateway
    from domain.contracts.config import settings
    from integrations.vm import mcp_client as vm_module

    monkeypatch.setattr(settings, "VM_MCP_URL", "http://vm.test/mcp")
    monkeypatch.setattr(settings, "SSH_ALLOWED_TARGETS", ["10.248.16.82"])
    monkeypatch.setattr(settings, "ELASTIC_SERVICE_DISCOVERY_ALIASES", {})
    requested = []

    class VM:
        async def service_status(self, target, service):
            requested.append(service)
            return {
                "success": True, "target": target, "service": service,
                "unit_id": "gfpapi.service", "load_state": "loaded",
                "active_state": "deactivating", "sub_state": "stop-sigterm",
            }
        async def close(self):
            pass
    monkeypatch.setattr(vm_module, "VMEdgeMCPClient", VM)
    discovery = {"status": "candidates_found", "candidates": [{
        "hostname": "apgfpdtnksa0101", "ip_addresses": ["10.248.16.82"],
    }]}
    evidence = await SignalGateway._verify_elastic_host_candidate(
        "GFP_Backend", discovery)
    assert requested == ["GFP_Backend"]
    assert evidence == []
    assert discovery["status"] == "candidates_found"
    assert discovery["candidates"][0]["verification_status"] == "vm_canonical_unit_mismatch"
    assert discovery["candidates"][0]["requested_runtime_unit"] == "gfp_backend"
    assert discovery["candidates"][0]["observed_canonical_unit"] == "gfpapi"
    assert discovery.get("verified_target") is None


@pytest.mark.asyncio
async def test_gfp_prefers_verified_canonical_runtime_with_systemd_id(monkeypatch):
    from apps.signal_gateway import SignalGateway
    from domain.contracts.config import settings
    from integrations.vm import mcp_client as vm_module

    monkeypatch.setattr(settings, "VM_MCP_URL", "http://vm.test/mcp")
    monkeypatch.setattr(settings, "SSH_ALLOWED_TARGETS", ["10.248.16.82"])
    monkeypatch.setattr(settings, "ELASTIC_SERVICE_DISCOVERY_ALIASES",
                        {"gfpapi": ["GFP_Backend"]})
    assert SignalGateway._runtime_service_candidates("GFP_Backend") == [
        "gfpapi", "GFP_Backend"
    ]
    requested = []

    class VM:
        async def service_status(self, target, service):
            requested.append(service)
            return {
                "success": True, "target": target, "service": service,
                "unit_id": "gfpapi.service", "load_state": "loaded",
                "active_state": "deactivating", "sub_state": "stop-sigterm",
            }
        async def close(self):
            pass
    monkeypatch.setattr(vm_module, "VMEdgeMCPClient", VM)
    discovery = {"status": "candidates_found", "candidates": [{
        "hostname": "apgfpdtnksa0101", "ip_addresses": ["10.248.16.82"],
    }]}
    evidence = await SignalGateway._verify_elastic_host_candidate(
        "GFP_Backend", discovery)
    assert requested == ["gfpapi"]
    assert discovery["verified_runtime_service"] == "gfpapi"
    assert discovery["mapping_status"] == "verified_live_vm_mcp"
    assert evidence[0]["raw_data"]["unit_id"] == "gfpapi.service"


def test_esql_fenced_json_is_decoded_without_executing_text():
    client = ElasticsearchMCPClient()
    response = {
        "structuredContent": {"status": "complete"},
        "content": [{"type": "text", "text": (
            "```json\n"
            '{"columns":[{"name":"@timestamp"},{"name":"service.name"},{"name":"message"}],'
            '"values":[["2026-10-20T05:25:00Z","GFP_Backend",'
            '"database connection refused"]]}'
            "\n```"
        )}],
    }
    selected = client._esql_payloads(response)
    assert len(selected) == 1
    rows = client._rows_from_payload(selected[0])
    assert len(rows) == 1
    assert rows[0]["service.name"] == "GFP_Backend"
    assert rows[0]["message"] == "database connection refused"
    assert client._esql_empty_table(selected[0]) is False


def test_esql_unknown_envelope_diagnostic_never_contains_log_or_secret():
    client = ElasticsearchMCPClient()
    payload = {
        "structuredContent": {"status": "complete", "token": "PRIVATE_PASSWORD"},
        "content": [{"type": "text", "text": "PRIVATE_PASSWORD"}],
        "password": "PRIVATE_PASSWORD",
    }
    shape = client._safe_envelope_shape(payload)
    assert shape["kind"] == "dict"
    assert "structuredContent" in shape["keys"]
    assert "content" in shape["keys"]
    assert "PRIVATE_PASSWORD" not in str(shape)
    assert "password" not in str(shape)
    assert "token" not in str(shape)
