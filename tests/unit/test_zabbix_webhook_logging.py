"""Zabbix Team Guide v1.1: every authenticated delivery is fully auditable.

The generic HTTP middleware truncates large bodies, so the dedicated Zabbix
ingress event must retain the entire original (redacted) payload and every
ordinary EVENT.TAGSJSON tag, even for rejected/duplicate/Recovery messages.
"""
from __future__ import annotations

import json
import logging
from pathlib import Path

import pytest
from fastapi import HTTPException

from apps.api import signals as signals_api
from domain.contracts import logging as logging_contract
from domain.contracts.config import settings
from domain.contracts.redaction import REDACTED, redact


class _Session:
    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False


@pytest.fixture
def json_log(tmp_path, monkeypatch):
    root = logging.getLogger()
    previous_handlers = list(root.handlers)
    previous_level = root.level
    monkeypatch.setattr(settings, "LOG_LEVEL", "INFO")
    monkeypatch.setattr(settings, "LOG_CONSOLE_ENABLED", False)
    monkeypatch.setattr(settings, "LOG_TEXT_FILE_ENABLED", False)
    monkeypatch.setattr(settings, "LOG_JSON_FILE_ENABLED", True)
    monkeypatch.setattr(settings, "LOG_DIR", str(tmp_path))
    monkeypatch.setattr(settings, "LOG_JSON_FILE", "zabbix-test.json.log")
    monkeypatch.setattr(settings, "LOG_ROTATION_MODE", "size")
    monkeypatch.setattr(settings, "LOG_MAX_BYTES", 10_000_000)
    monkeypatch.setattr(settings, "LOG_BACKUP_COUNT", 2)
    logging_contract.configure_logging()
    path = Path(tmp_path) / "zabbix-test.json.log"
    try:
        yield path
    finally:
        for handler in root.handlers:
            handler.flush()
            handler.close()
        root.handlers = previous_handlers
        root.setLevel(previous_level)


def _records(path):
    for handler in logging.getLogger().handlers:
        handler.flush()
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def _ingress(records):
    return [item for item in records if item.get("event") == "zabbix_webhook_received"]


def test_sensitive_event_tags_are_redacted_without_dropping_normal_tags():
    tags = [
        {"tag": "service", "value": "payment-api"},
        {"tag": "api_key", "value": "should-never-leak"},
        {"tag": "password", "value": "secret-password"},
        {"tag": "owner", "value": "platform"},
    ]
    actual = redact({"payload": {"tags": tags, "x-api-key": "header-secret"}})
    assert actual["payload"]["tags"][0] == tags[0]
    assert actual["payload"]["tags"][1]["value"] == REDACTED
    assert actual["payload"]["tags"][2]["value"] == REDACTED
    assert actual["payload"]["tags"][3] == tags[3]
    assert actual["payload"]["x-api-key"] == REDACTED

    json_tags = redact({"tags": json.dumps(tags)})["tags"]
    parsed = json.loads(json_tags)
    assert parsed[0] == tags[0]
    assert parsed[1]["value"] == REDACTED
    assert parsed[2]["value"] == REDACTED
    assert "should-never-leak" not in json_tags


@pytest.mark.asyncio
async def test_entire_original_problem_and_all_tags_are_logged_even_beyond_http_body_limit(
    json_log, monkeypatch
):
    async def ready(db):
        return None

    async def ingest(db, payload):
        assert payload["service"] == "payment-api"
        return {
            "status": "accepted",
            "incident_id": "incident-123",
            "signal_state": "problem",
            "deduplicated": False,
        }

    monkeypatch.setattr(signals_api, "AsyncSessionLocal", _Session)
    monkeypatch.setattr(signals_api, "_require_database_ready", ready)
    monkeypatch.setattr(signals_api, "ingest_zabbix_payload", ingest)
    monkeypatch.setattr(settings, "LOG_HTTP_BODY_MAX_BYTES", 256)

    tags = [{"tag": f"custom_{i}", "value": "x" * 150} for i in range(75)]
    tags.extend([
        {"tag": "service", "value": "payment-api"},
        {"tag": "platform", "value": "vm"},
        {"tag": "target_ip", "value": "10.20.10.15"},
        {"tag": "token", "value": "secret-token-from-zabbix"},
    ])
    payload = {
        "eventid": "501001",
        "event_value": "1",
        "event_status": "PROBLEM",
        "name": "VM memory usage is high",
        "severity": "High",
        "hostid": "42",
        "host": "payment-vm-01",
        "host_name": "Payments VM",
        "host_ip": "10.20.10.99",
        "triggerid": "21001",
        "trigger": "Memory utilization high",
        "operational_data": "Memory utilization=94%",
        "timestamp": "1791712800",
        "acknowledged": "No",
        "tags": tags,
        "extra_webhook_field": {"nested": {"disk": "93%", "list": ["a", "b"]}},
    }
    response = await signals_api._ingest_zabbix(payload)
    assert response["incident_id"] == "incident-123"
    rows = _records(json_log)
    received = _ingress(rows)
    assert len(received) == 1
    assert received[0]["log_type"] == "zabbix_webhook"
    assert received[0]["phase"] == "received"
    raw = received[0]["raw_request"]["payload"]
    assert raw["eventid"] == payload["eventid"]
    for key, val in payload.items():
        if key != "tags":
            assert raw[key] == val
    assert len(raw["tags"]) == len(tags)
    assert raw["tags"][-4:-1] == tags[-4:-1]
    assert raw["tags"][-1]["value"] == REDACTED
    assert "secret-token-from-zabbix" not in json_log.read_text(encoding="utf-8")
    assert len(json.dumps(raw, ensure_ascii=False)) > settings.LOG_HTTP_BODY_MAX_BYTES

    processed = [row for row in rows if row.get("event") == "zabbix_webhook_processed"]
    assert len(processed) == 1
    assert processed[0]["incident_id"] == "incident-123"
    assert processed[0]["signal_state"] == "problem"
    assert processed[0]["http_status"] == 200


@pytest.mark.asyncio
async def test_recovery_and_duplicate_are_logged_as_separate_deliveries(json_log, monkeypatch):
    async def ready(db):
        return None

    async def ingest(db, payload):
        return {
            "status": "accepted",
            "incident_id": "incident-123",
            "signal_state": "recovery",
            "deduplicated": True,
            "recovered": True,
        }

    monkeypatch.setattr(signals_api, "AsyncSessionLocal", _Session)
    monkeypatch.setattr(signals_api, "_require_database_ready", ready)
    monkeypatch.setattr(signals_api, "ingest_zabbix_payload", ingest)
    original = {
        "eventid": "501001", "recovery_eventid": "501009",
        "event_value": "0", "event_status": "RESOLVED",
        "tags": [{"tag": "service", "value": "payment-api"}],
    }
    await signals_api._ingest_zabbix(original)
    await signals_api._ingest_zabbix(original)
    events = _records(json_log)
    assert len(_ingress(events)) == 2
    assert all(row["raw_request"]["payload"] == original for row in _ingress(events))
    completed = [row for row in events if row.get("event") == "zabbix_webhook_processed"]
    assert len(completed) == 2
    assert all(row["deduplicated"] is True for row in completed)
    assert all(row["signal_state"] == "recovery" for row in completed)


@pytest.mark.asyncio
async def test_invalid_eventid_still_logs_original_payload_and_rejection(json_log, monkeypatch):
    def should_not_connect():
        raise AssertionError("invalid event identity should never reach DB")

    monkeypatch.setattr(signals_api, "AsyncSessionLocal", should_not_connect)
    invalid = {
        "eventid": "{EVENT.ID}", "event_value": "1",
        "tags": [{"tag": "service", "value": "payment-api"}],
        "custom": {"note": "as received"},
    }
    with pytest.raises(HTTPException) as exc:
        await signals_api._ingest_zabbix(invalid)
    assert exc.value.status_code == 422
    events = _records(json_log)
    assert _ingress(events)[0]["raw_request"]["payload"] == invalid
    rejected = next(row for row in events if row.get("event") == "zabbix_webhook_rejected")
    assert rejected["http_status"] == 422
    assert rejected["eventid"] == "{EVENT.ID}"


@pytest.mark.asyncio
async def test_unmatched_recovery_logs_failure_and_original_fields(json_log, monkeypatch):
    async def ready(db):
        return None

    async def ingest(db, payload):
        return {
            "signal_state": "recovery",
            "recovery_unmatched": True,
            "terminal_reason": "zabbix_recovery_problem_event_not_found",
        }

    monkeypatch.setattr(signals_api, "AsyncSessionLocal", _Session)
    monkeypatch.setattr(signals_api, "_require_database_ready", ready)
    monkeypatch.setattr(signals_api, "ingest_zabbix_payload", ingest)
    recovery = {
        "eventid": "501001", "recovery_eventid": "501009",
        "event_value": "0", "event_status": "RESOLVED",
        "tags": [{"tag": "service", "value": "payment-api"}],
    }
    with pytest.raises(HTTPException) as exc:
        await signals_api._ingest_zabbix(recovery)
    assert exc.value.status_code == 503
    events = _records(json_log)
    assert _ingress(events)[0]["raw_request"]["payload"] == recovery
    rejected = next(row for row in events if row.get("event") == "zabbix_webhook_rejected")
    assert rejected["http_status"] == 503
    assert rejected["reason"] == "zabbix_recovery_problem_event_not_found"
