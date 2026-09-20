from __future__ import annotations

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
