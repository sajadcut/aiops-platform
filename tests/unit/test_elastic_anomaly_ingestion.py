from __future__ import annotations

import pytest

from domain.contracts.config import settings
from apps.signal_gateway.elastic_anomaly import (
    classify_elastic_anomaly_lifecycle,
    normalize_elastic_anomaly_payload,
    signal_from_elastic_anomaly,
)


def _active_payload() -> dict:
    return {
        "schema_version": "1.0",
        "source": "elastic",
        "event_type": "ml_anomaly",
        "state": "active",
        "scheduled_at": "2026-09-19T10:11:30Z",
        "rule": {
            "id": "rule-1",
            "name": "payment latency anomaly",
            "space_id": "default",
            "tags": '["team:sre"]',
        },
        "alert": {
            "id": "alert-1",
            "uuid": "alert-uuid-1",
            "action_group": "anomaly_score_match",
        },
        "anomaly": {
            "score": "82.5",
            "timestamp_iso8601": "2026-09-19T10:10:00Z",
            "is_interim": "false",
            "job_ids": '["payment-latency-job"]',
            "message": "response latency is unusual",
            "top_influencers": '[{"influencer_field_name":"service.name","influencer_field_value":"payment-api","score":82.5}]',
            "top_records": '[{"function":"mean","field_name":"response_time","actual":[4521],"typical":[320],"score":82.5}]',
        },
    }


def test_official_anomaly_payload_becomes_first_class_alert_signal():
    signal = signal_from_elastic_anomaly(_active_payload())
    evidence = signal.to_evidence()

    assert signal.source == "elasticsearch"
    assert signal.source_id == "alert-uuid-1"
    assert signal.service == "payment-api"
    assert signal.severity == "critical"
    assert signal.timestamp.isoformat() == "2026-09-19T10:10:00+00:00"
    assert signal.signal_type == "ml_anomaly:mean:response_time"
    assert evidence["type"] == "alert"
    assert evidence["raw_data"]["elastic_alert_kind"] == "ml_anomaly"
    assert evidence["raw_data"]["anomaly"]["score"] == 82.5


def test_elastic_anomaly_source_id_is_stable_without_alert_uuid():
    payload = _active_payload()
    payload["alert"] = {}
    left = signal_from_elastic_anomaly(payload)
    right = signal_from_elastic_anomaly(payload)
    assert left.source_id == right.source_id
    assert left.source_id.startswith("elastic-ml:")


def test_job_service_map_is_deterministic_fallback(monkeypatch):
    payload = _active_payload()
    payload["service"] = ""
    payload["rule"]["tags"] = "[]"
    payload["anomaly"]["top_influencers"] = "[]"
    monkeypatch.setattr(settings, "ELASTIC_ANOMALY_JOB_SERVICE_MAP", {"payment-latency-job": "mapped-payment-api"})

    signal = signal_from_elastic_anomaly(payload)
    assert signal.service == "mapped-payment-api"


def test_recovery_reuses_problem_identity_and_has_stable_recovery_reference():
    payload = _active_payload()
    active = classify_elastic_anomaly_lifecycle(payload)

    payload["state"] = "recovered"
    payload["alert"]["action_group"] = "recovered"
    first = classify_elastic_anomaly_lifecycle(payload)
    second = classify_elastic_anomaly_lifecycle(payload)

    assert active["problem_event_id"] == "alert-uuid-1"
    assert first["problem_event_id"] == active["problem_event_id"]
    assert first["recovery_event_id"] == second["recovery_event_id"]
    assert first["recovery_event_id"] != first["problem_event_id"]


def test_json_encoded_action_variables_are_normalized():
    normalized = normalize_elastic_anomaly_payload(_active_payload())
    assert normalized["anomaly"]["job_ids"] == ["payment-latency-job"]
    assert normalized["anomaly"]["is_interim"] is False
    assert normalized["anomaly"]["top_influencers"][0]["influencer_field_name"] == "service.name"


def test_native_json_arrays_from_asjson_webhook_are_normalized():
    payload = _active_payload()
    payload["rule"]["tags"] = ["team:sre", "service:payment-api"]
    payload["anomaly"]["job_ids"] = ["payment-latency-job"]
    payload["anomaly"]["top_influencers"] = [
        {
            "influencer_field_name": "service.name",
            "influencer_field_value": "payment-api",
            "score": 82.5,
        }
    ]
    payload["anomaly"]["top_records"] = [
        {
            "function": "mean",
            "field_name": "response_time",
            "actual": [4521],
            "typical": [320],
            "score": 82.5,
        }
    ]

    normalized = normalize_elastic_anomaly_payload(payload)
    assert normalized["rule"]["tags"] == ["team:sre", "service:payment-api"]
    assert normalized["anomaly"]["job_ids"] == ["payment-latency-job"]
    assert normalized["anomaly"]["top_influencers"][0]["influencer_field_value"] == "payment-api"
    assert normalized["anomaly"]["top_records"][0]["field_name"] == "response_time"


@pytest.mark.asyncio
async def test_nested_threshold_webhook_is_not_silently_misclassified_as_ml(monkeypatch):
    from apps.api import signals as api
    import pytest
    # Use the actual endpoint with an in-memory ingestion boundary, no DB/MCP.
    sample = {
        "payload": {
            "id": "query matched", "service": "GFP_Backend",
            "severity": "high",
            "message": "GFP Redis errors reached at least 10 events in the last 2 minutes.",
            "event": {"kind": "alert", "action": "redis_error_threshold",
                      "correlation_key": "GFP_Backend:redis"},
            "rule": {"name": "GFP Redis Error Threshold - AIOps"},
            "observed_count": "443",
            "timestamp": "2026-10-17T08:57:46Z",
        }
    }
    seen = []
    async def fake_ingest(signal):
        seen.append(signal)
        return {"status": "accepted", "incident_id": "test"}
    async def must_not_use_ml(_):
        raise AssertionError("Custom threshold was routed to ML anomaly handler")
    monkeypatch.setattr(api, "_ingest", fake_ingest)
    monkeypatch.setattr(api, "_ingest_elastic_anomaly", must_not_use_ml)
    body = api.ElasticAnomalyWebhookPayload(**sample)
    response = await api.ingest_elasticsearch_anomaly(None, body, _user=None)
    assert response["incident_id"] == "test"
    signal = seen[0]
    assert signal.service == "GFP_Backend"  # no speculative rename to gfpapi
    assert signal.severity == "high"
    assert signal.signal_type == "redis_error_threshold"
    assert signal.correlation_key == "GFP_Backend:redis"
    assert "Redis errors" in signal.summary
    assert signal.raw_data["_received_payload"] is not None


@pytest.mark.asyncio
async def test_generic_threshold_duplicate_identity_requires_event_context():
    from apps.signal_gateway import signal_from_elasticsearch
    template = {
        "id": "query matched", "service": "GFP_Backend",
        "message": "GFP Redis errors reached 10 events",
        "event": {"action": "redis_error_threshold"},
        "timestamp": "2026-10-17T08:53:00Z", "observed_count": "443",
    }
    original = signal_from_elasticsearch(template)
    repeated = signal_from_elasticsearch(dict(template))
    changed = signal_from_elasticsearch({**template, "timestamp": "2026-10-17T08:58:00Z"})
    assert original.source_id == repeated.source_id
    assert original.source_id != changed.source_id
    assert original.source_id.startswith("elastic-event:")


@pytest.mark.asyncio
async def test_nested_ml_webhook_still_uses_ml_lifecycle(monkeypatch):
    from apps.api import signals as api
    recorded = []
    async def fake_ml(payload):
        recorded.append(payload)
        return {"incident_id": "ml-test", "trigger_source": "elasticsearch"}
    async def never_generic(_):
        raise AssertionError("ML event routed as generic signal")
    monkeypatch.setattr(api, "_ingest_elastic_anomaly", fake_ml)
    monkeypatch.setattr(api, "_ingest", never_generic)
    response = await api.ingest_elasticsearch_anomaly(
        None, api.ElasticAnomalyWebhookPayload(payload=_active_payload()), _user=None)
    assert response["incident_id"] == "ml-test"
    assert recorded[0]["anomaly"]["score"] == "82.5"
