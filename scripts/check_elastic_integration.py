"""Read-only Elastic integration acceptance probe.

Usage (from repository root):
    python -m scripts.check_elastic_integration
    python -m scripts.check_elastic_integration --service GFP_Backend --api-base-url http://localhost:8000

The live MCP checks issue bounded, read-only ES|QL queries. No webhook POST,
ML job creation, connector change or incident mutation is performed.
Never print secrets or returned log contents from this script.
"""
from __future__ import annotations

import argparse
import asyncio
from datetime import datetime, timedelta, timezone
from typing import Any, Optional
from urllib.parse import urlsplit

import httpx

from apps.signal_gateway.elastic_anomaly import (
    ElasticAnomalyWebhookPayload,
    classify_elastic_anomaly_lifecycle,
    normalize_elastic_anomaly_payload,
    signal_from_elastic_anomaly,
)
from domain.contracts.config import settings
from integrations.elasticsearch.mcp_client import ElasticsearchMCPClient
from scripts.check_elastic_mcp import _http_status, _safe_endpoint


# Explicit, read-only field names. Never interpolate names discovered from
# untrusted remote data into a query; only these locally approved names.
SERVICE_FIELDS = (
    "service.name",
    "service",
    "Properties.ServiceName.keyword",
    "Properties.ServiceName",
)
MESSAGE_FIELDS = ("message", "MessageTemplate")
LEVEL_FIELDS = ("log.level", "level", "Level")
TIMESTAMP_FIELDS = ("@timestamp", "Timestamp")


def _field(row: dict[str, Any], names: tuple[str, ...]) -> tuple[str, Any] | None:
    for name in names:
        value = row.get(name)
        if value is not None and str(value).strip():
            return name, value
    return None


def _timestamp(value: Any) -> datetime | None:
    try:
        value = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)
    except (ValueError, TypeError):
        return None


def _rows(client: ElasticsearchMCPClient, response: dict[str, Any]) -> list[dict[str, Any]]:
    found: list[dict[str, Any]] = []
    for item in client.json_content(response):
        found.extend(client._rows_from_payload(item))
    return found


def _error(error: Exception) -> str:
    status = _http_status(error)
    if status == 401:
        return "HTTP 401: check the effective MCP credentials"
    if status == 403:
        return "HTTP 403: check Kibana Space and Agent Builder / index permissions"
    if status is not None:
        return f"HTTP {status}: inspect the Kibana service logs"
    # Intentionally do not print remote exception messages: those may contain
    # record values, URLs, credentials or ES|QL query fragments.
    return f"{type(error).__name__}: check MCP/AIOps logs (do not share raw log bodies)"


class Report:
    def __init__(self):
        self.failures = 0
        self.incomplete = 0

    def pass_(self, label: str, detail: str = ""):
        print(f"PASS {label}" + (f": {detail}" if detail else ""))

    def fail(self, label: str, detail: str):
        self.failures += 1
        print(f"FAIL {label}: {detail}")

    def not_tested(self, label: str, detail: str):
        self.incomplete += 1
        print(f"NOT TESTED {label}: {detail}")

    def summary(self) -> int:
        print(f"\nSUMMARY failures={self.failures}, not_tested={self.incomplete}")
        if self.failures:
            print("RESULT: FAIL (some required acceptance checks failed)")
            return 1
        if self.incomplete:
            print("RESULT: PARTIAL (remaining checks were not exercised)")
            return 2
        print("RESULT: PASS")
        return 0


def check_anomaly_contract(report: Report) -> None:
    """Dry-run active/recovered webhook payloads without a database write."""
    active = {
        "schema_version": "1.0",
        "source": "elastic",
        "event_type": "ml_anomaly",
        "state": "active",
        "scheduled_at": "2026-10-13T10:00:00Z",
        "rule": {"id": "diagnostic-rule", "tags": '["service:probe-api"]'},
        "alert": {"uuid": "diagnostic-alert", "action_group": "anomaly_score_match"},
        "anomaly": {
            "score": "83",
            "timestamp_iso8601": "2026-10-13T09:59:00Z",
            "is_interim": "false",
            "job_ids": '["diagnostic-job"]',
            "top_influencers": "[]",
            "top_records": "[]",
        },
    }
    try:
        payload = ElasticAnomalyWebhookPayload.model_validate(active)
        normalized = normalize_elastic_anomaly_payload(payload.model_dump(mode="json"))
        signal = signal_from_elastic_anomaly(active)
        first = classify_elastic_anomaly_lifecycle(active)
        recovered = {**active, "state": "recovered"}
        last = classify_elastic_anomaly_lifecycle(recovered)
        assert normalized["anomaly"]["job_ids"] == ["diagnostic-job"]
        assert normalized["anomaly"]["is_interim"] is False
        assert signal.service == "probe-api" and signal.severity == "critical"
        assert first["problem_event_id"] == last["problem_event_id"]
        assert first["state"] == "active" and last["state"] == "recovery"
        assert last["recovery_event_id"] != first["problem_event_id"]
    except Exception as error:
        report.fail("anomaly payload + recovery contract", type(error).__name__)
    else:
        report.pass_("anomaly payload + recovery contract", "local only; no incident created")


async def check_api_route(report: Report, base_url: str | None) -> None:
    if not base_url:
        report.not_tested("AIOps webhook route", "pass --api-base-url to inspect live OpenAPI")
        return
    parsed = urlsplit(base_url)
    if parsed.scheme not in ("http", "https") or not parsed.netloc or parsed.username or parsed.password:
        report.fail("AIOps webhook route", "invalid API base URL")
        return
    try:
        async with httpx.AsyncClient(timeout=8.0, follow_redirects=False, trust_env=False) as session:
            response = await session.get(base_url.rstrip("/") + "/openapi.json")
        response.raise_for_status()
        spec = response.json()
        operation = spec.get("paths", {}).get("/api/v1/signals/elasticsearch/anomaly", {}).get("post")
        if not isinstance(operation, dict):
            report.fail("AIOps webhook route", "POST /api/v1/signals/elasticsearch/anomaly missing")
            return
        if not operation.get("security"):
            report.fail("AIOps webhook route", "OpenAPI operation has no declared authentication")
            return
        report.pass_("AIOps webhook route", "POST endpoint documented with security requirements")
    except Exception as error:
        report.fail("AIOps webhook route", _error(error))


async def run_checks(
    client: ElasticsearchMCPClient,
    *,
    service: str | None,
    api_base_url: str | None,
    report: Report,
) -> int:
    try:
        endpoint, namespace, scheme = _safe_endpoint(client.server_url)
        auth = client._headers(include_protocol=False).get("Authorization", "")
        print(f"MCP endpoint: {endpoint}")
        print(f"MCP namespace: {namespace}")
        print(f"Index pattern: {settings.ELASTIC_AGENT_BUILDER_INDEX_PATTERN}")
        print(f"Authentication scheme: {auth.split(' ', 1)[0] if auth else 'none'}")
        if scheme != "https":
            print("WARNING: MCP credentials are being sent over unencrypted HTTP.")
        if not auth:
            report.fail("MCP authentication config", "missing Authorization header")
        else:
            report.pass_("MCP authentication config")

        try:
            assert client.allowed_tools == frozenset({client.TOOL_EXECUTE_ESQL})
            try:
                await client.call_tool("platform_core_search", {"query": "do-not-send"})
            except PermissionError:
                report.pass_("read-only MCP allowlist", "other tools blocked locally")
            else:
                report.fail("read-only MCP allowlist", "disallowed tool was callable")
        except Exception:
            report.fail("read-only MCP allowlist", "unexpected tool policy")
        if not auth:
            report.not_tested("MCP live handshake / evidence", "provide MCP credentials")
            check_anomaly_contract(report)
            await check_api_route(report, api_base_url)
            return report.summary()

        try:
            await client.initialize()
            report.pass_("MCP initialize")
            tools = await client.list_tools()
            names = {item.get("name") for item in tools}
            if client.TOOL_EXECUTE_ESQL not in names:
                report.fail("MCP tool discovery", "platform_core_execute_esql not available")
                check_anomaly_contract(report)
                await check_api_route(report, api_base_url)
                return report.summary()
            report.pass_("MCP tool discovery", "platform_core_execute_esql")
        except Exception as error:
            report.fail("MCP handshake / discovery", _error(error))
            check_anomaly_contract(report)
            await check_api_route(report, api_base_url)
            return report.summary()

        try:
            query = f"FROM {settings.ELASTIC_AGENT_BUILDER_INDEX_PATTERN} | LIMIT 1"
            response = await client.call_tool(client.TOOL_EXECUTE_ESQL, {"query": query})
            rows = _rows(client, response)
            if not rows:
                report.fail("ES|QL read / response parsing", "no rows decoded; verify matching index data")
                check_anomaly_contract(report)
                await check_api_route(report, api_base_url)
                return report.summary()
            report.pass_("ES|QL read / response parsing", f"{len(rows)} row(s); contents hidden")
        except Exception as error:
            report.fail("ES|QL read / response parsing", _error(error))
            check_anomaly_contract(report)
            await check_api_route(report, api_base_url)
            return report.summary()

        row = rows[0]
        sf = _field(row, SERVICE_FIELDS)
        mf = _field(row, MESSAGE_FIELDS)
        lf = _field(row, LEVEL_FIELDS)
        tf = _field(row, TIMESTAMP_FIELDS)
        if sf and mf and lf and tf and _timestamp(tf[1]):
            report.pass_(
                "sample schema detection",
                f"service={sf[0]}, message={mf[0]}, level={lf[0]}, timestamp={tf[0]}",
            )
        else:
            report.fail(
                "sample schema detection",
                "missing service/message/level/timestamp in sampled document",
            )

        if sf and tf and _timestamp(tf[1]):
            selected_service = service or str(sf[1])
            timestamp = _timestamp(tf[1])
            assert timestamp is not None
            # Filter names come exclusively from the local SERVICE_FIELDS allowlist.
            safe_service = client._esql_string(selected_service)
            filter_query = (
                f"FROM {settings.ELASTIC_AGENT_BUILDER_INDEX_PATTERN}"
                f" | WHERE {sf[0]} == {safe_service}"
                f" | SORT {tf[0]} DESC | KEEP {tf[0]}, {sf[0]} | LIMIT 5"
            )
            try:
                filtered = _rows(
                    client,
                    await client.call_tool(client.TOOL_EXECUTE_ESQL, {"query": filter_query}),
                )
                if filtered and all(str(item.get(sf[0])) == selected_service for item in filtered):
                    report.pass_("ES|QL service filter", f"matched {len(filtered)} row(s)")
                else:
                    report.fail("ES|QL service filter", "no matching rows or mismatched service")
            except Exception as error:
                report.fail("ES|QL service filter", _error(error))

            try:
                results = await client.get_logs(
                    selected_service,
                    since=timestamp - timedelta(minutes=2),
                    until=timestamp + timedelta(minutes=2),
                    limit=5,
                )
                if not results:
                    report.fail(
                        "AIOps LogEntry adapter",
                        "no service/time-matched log entries; check ECS vs Properties.* mapping",
                    )
                elif any(
                    item.service != selected_service
                    or not item.message.strip()
                    or not (timestamp - timedelta(minutes=2) <= item.timestamp <= timestamp + timedelta(minutes=2))
                    for item in results
                ):
                    report.fail("AIOps LogEntry adapter", "incorrect service/message/time normalization")
                else:
                    report.pass_("AIOps LogEntry adapter", f"{len(results)} valid log(s); contents hidden")
            except Exception as error:
                report.fail(
                    "AIOps LogEntry adapter",
                    _error(error) + "; check schema mapping (service.name vs Properties.ServiceName)",
                )
        else:
            report.not_tested("ES|QL service filter / LogEntry", "no sample service/timestamp to anchor tests")

        check_anomaly_contract(report)
        await check_api_route(report, api_base_url)
        report.not_tested(
            "Kibana ML job + connector + real webhook delivery",
            "requires a real ML rule firing and AIOps incident/recovery verification",
        )
        return report.summary()
    finally:
        await client.close()


def main() -> int:
    parser = argparse.ArgumentParser(description="Read-only Elastic AIOps integration acceptance test")
    parser.add_argument("--service", help="Optional service name for service-filter and LogEntry checks")
    parser.add_argument(
        "--api-base-url",
        help="Optional AIOps API root for read-only OpenAPI webhook-route check",
    )
    args = parser.parse_args()
    try:
        client = ElasticsearchMCPClient()
    except Exception as error:
        print(f"FAIL MCP configuration: {type(error).__name__}")
        return 1
    return asyncio.run(
        run_checks(client, service=args.service, api_base_url=args.api_base_url, report=Report())
    )


if __name__ == "__main__":
    raise SystemExit(main())
