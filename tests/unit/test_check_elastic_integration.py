"""Offline, network-free acceptance tests for the Elastic live probe."""
from __future__ import annotations

import asyncio
from datetime import datetime, timezone

import httpx

from scripts.check_elastic_integration import (
    Report,
    _rows,
    _timestamp,
    check_anomaly_contract,
    check_api_route,
    run_checks,
)


class FakeClient:
    TOOL_EXECUTE_ESQL = "platform_core_execute_esql"
    allowed_tools = frozenset({"platform_core_execute_esql"})
    server_url = "https://kibana.example/s/mcp/api/agent_builder/mcp?namespace=platform.core"

    def __init__(self, *, raw=None, logs=None, error=None, auth="Basic fake"):
        self.raw = raw or {
            "content": [{"type": "text", "text": '{"results":[{"type":"tabular_data","data":{"columns":[{"name":"@timestamp"},{"name":"Properties.ServiceName.keyword"},{"name":"MessageTemplate"},{"name":"Level"}],"values":[["2026-10-12T07:01:35Z","GFP_Backend","SECRET LOG MESSAGE","Information"]]}}]}'}]
        }
        self.logs = logs if logs is not None else []
        self.error = error
        self.auth = auth
        self.closed = False
        self.calls = []

    def _headers(self, **kwargs):
        return {"Authorization": self.auth} if self.auth else {}

    async def initialize(self):
        if self.error:
            raise self.error

    async def list_tools(self):
        return [{"name": self.TOOL_EXECUTE_ESQL}]

    async def call_tool(self, name, arguments):
        if name not in self.allowed_tools:
            raise PermissionError("not allowed")
        self.calls.append(arguments["query"])
        return self.raw

    @staticmethod
    def _esql_string(value):
        return '"' + str(value).replace("\\", "\\\\").replace('"', '\\"') + '"'

    @staticmethod
    def json_content(response):
        import json
        return [json.loads(part["text"]) for part in response["content"]]

    @staticmethod
    def _rows_from_payload(payload):
        items = []
        for result in payload.get("results", []):
            data = result.get("data", {})
            cols = data.get("columns", [])
            for values in data.get("values", []):
                items.append({c["name"]: value for c, value in zip(cols, values)})
        return items

    async def get_logs(self, service, since, until, limit):
        return self.logs

    async def close(self):
        self.closed = True


def test_anomaly_active_recovery_contract_is_read_only(capsys):
    report = Report()
    check_anomaly_contract(report)
    assert report.failures == 0
    assert "PASS anomaly payload + recovery contract" in capsys.readouterr().out


def test_parses_real_kibana_tabular_mcp_shape_without_printing_log(capsys):
    client = FakeClient()
    rows = _rows(client, client.raw)
    assert len(rows) == 1
    assert rows[0]["Properties.ServiceName.keyword"] == "GFP_Backend"
    report = Report()
    code = asyncio.run(run_checks(client, service="GFP_Backend", api_base_url=None, report=report))
    output = capsys.readouterr().out
    assert code == 1  # Real connection alone does not validate a broken LogEntry adapter.
    assert "PASS ES|QL read / response parsing" in output
    assert "FAIL AIOps LogEntry adapter" in output
    assert "NOT TESTED Kibana ML job + connector" in output
    assert "SECRET LOG MESSAGE" not in output
    assert client.closed


def test_log_entry_adapter_validates_message_service_and_time(capsys):
    from integrations.base import LogEntry
    client = FakeClient(logs=[LogEntry(
        timestamp=datetime(2026, 10, 12, 7, 1, 35, tzinfo=timezone.utc),
        service="GFP_Backend",
        level="Information",
        message="SECRET LOG MESSAGE",
        source="elasticsearch",
    )])
    report = Report()
    code = asyncio.run(run_checks(client, service=None, api_base_url=None, report=report))
    output = capsys.readouterr().out
    assert code == 2  # The live Kibana ML rule/webhook path still needs real acceptance.
    assert "PASS AIOps LogEntry adapter" in output
    assert "SECRET LOG MESSAGE" not in output
    assert client.closed


def test_401_handshake_is_not_misreported_as_success(capsys):
    request = httpx.Request("POST", "https://kibana.example/s/mcp/api/agent_builder/mcp")
    response = httpx.Response(401, request=request)
    client = FakeClient(error=httpx.HTTPStatusError("secret body", request=request, response=response))
    code = asyncio.run(run_checks(client, service=None, api_base_url=None, report=Report()))
    assert code == 1
    output = capsys.readouterr().out
    assert "HTTP 401" in output
    assert "secret body" not in output
    assert client.closed


def test_no_credentials_skips_network(capsys):
    client = FakeClient(auth="")
    code = asyncio.run(run_checks(client, service=None, api_base_url=None, report=Report()))
    assert code == 1
    assert "missing Authorization header" in capsys.readouterr().out
    assert not client.calls
    assert client.closed


def test_timestamp_parser_requires_real_dates():
    assert _timestamp("invalid") is None
    assert _timestamp("2026-10-12T07:01:35.204Z").tzinfo is not None


def test_webhook_route_check_is_explicitly_not_tested_without_api_url(capsys):
    report = Report()
    asyncio.run(check_api_route(report, None))
    assert report.incomplete == 1
    assert "NOT TESTED" in capsys.readouterr().out


def test_webhook_route_openapi_read_only(monkeypatch, capsys):
    class FakeResponse:
        def raise_for_status(self):
            pass
        def json(self):
            return {"paths": {"/api/v1/signals/elasticsearch/anomaly": {
                "post": {"security": [{"APIKeyHeader": []}]}
            }}}
    class FakeSession:
        async def __aenter__(self):
            return self
        async def __aexit__(self, *args):
            pass
        async def get(self, url):
            assert url == "http://localhost:8000/openapi.json"
            return FakeResponse()
    monkeypatch.setattr(
        "scripts.check_elastic_integration.httpx.AsyncClient",
        lambda **kwargs: FakeSession(),
    )
    report = Report()
    asyncio.run(check_api_route(report, "http://localhost:8000"))
    assert report.failures == 0
    assert "PASS AIOps webhook route" in capsys.readouterr().out
