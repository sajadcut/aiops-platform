import json
from datetime import datetime, timezone

import pytest

from domain.contracts.config import settings
from integrations.prometheus.mcp_client import PrometheusMCPClient


def _client() -> PrometheusMCPClient:
    return PrometheusMCPClient("http://prometheus-mcp:8080/mcp")


def test_official_prometheus_contract_uses_provider_protocol_and_no_generic_bearer():
    client = _client()
    try:
        assert client.protocol_version == "2025-11-25"
        assert client.protocol_version == settings.PROMETHEUS_MCP_PROTOCOL_VERSION
        assert client.bearer_token is None
        assert "ready" in client.allowed_tools
        assert "range_query" in client.allowed_tools
    finally:
        import asyncio

        asyncio.run(client.close())


@pytest.mark.asyncio
async def test_range_query_parses_official_prometheus_model_text(monkeypatch):
    client = _client()

    official_result = {
        "result": (
            'http_requests_total{instance="api-1", service="payments"} =>\n'
            "1.5 @[1756143048]\n"
            "2 @[1756143063]\n"
        ),
        "warnings": None,
    }

    async def fake_call_tool(tool_name, arguments):
        assert tool_name == "range_query"
        assert arguments["query"] == 'http_requests_total{service="payments"}'
        assert arguments["truncation_limit"] == 200
        return {
            "content": [
                {
                    "type": "text",
                    "text": json.dumps(official_result),
                }
            ]
        }

    monkeypatch.setattr(client, "call_tool", fake_call_tool)
    try:
        points = await client.get_metrics(
            "payments",
            ["http_requests_total"],
            datetime(2026, 9, 19, tzinfo=timezone.utc),
        )
    finally:
        await client.close()

    assert len(points) == 2
    assert points[0].name == "http_requests_total"
    assert points[0].service == "payments"
    assert points[0].value == 1.5
    assert points[0].labels["instance"] == "api-1"
    assert points[0].timestamp == datetime.fromtimestamp(1756143048, tz=timezone.utc)
    assert points[1].value == 2.0


@pytest.mark.asyncio
async def test_range_query_keeps_legacy_structured_payload_compatibility(monkeypatch):
    client = _client()

    async def fake_call_tool(tool_name, arguments):
        return {
            "structuredContent": {
                "metric": {
                    "__name__": "cpu_usage",
                    "service": "payments",
                    "instance": "vm-1",
                },
                "values": [[1756143048, "42.5"]],
            }
        }

    monkeypatch.setattr(client, "call_tool", fake_call_tool)
    try:
        points = await client.get_metrics(
            "payments",
            ["cpu_usage"],
            datetime(2026, 9, 19, tzinfo=timezone.utc),
        )
    finally:
        await client.close()

    assert len(points) == 1
    assert points[0].name == "cpu_usage"
    assert points[0].value == 42.5
    assert points[0].labels["instance"] == "vm-1"


@pytest.mark.asyncio
async def test_health_check_uses_official_ready_tool(monkeypatch):
    client = _client()
    calls = []

    async def fake_call_tool(tool_name, arguments):
        calls.append((tool_name, arguments))
        return {"content": [{"type": "text", "text": "Prometheus is Ready."}]}

    monkeypatch.setattr(client, "call_tool", fake_call_tool)
    try:
        assert await client.health_check() is True
    finally:
        await client.close()

    assert calls == [("ready", {})]
