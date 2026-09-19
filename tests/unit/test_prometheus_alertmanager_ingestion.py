from __future__ import annotations

from apps.signal_gateway.prometheus_alertmanager import (
    AlertmanagerWebhookPayload,
    _signal_from_alert,
    classify_alertmanager_alert,
)


def _payload() -> dict:
    return {
        "version": "4",
        "groupKey": "{}:{alertname=\"HighErrorRate\"}",
        "truncatedAlerts": 0,
        "status": "firing",
        "receiver": "aiops-platform",
        "groupLabels": {"alertname": "HighErrorRate"},
        "commonLabels": {
            "alertname": "HighErrorRate",
            "service": "payment-api",
            "severity": "critical",
        },
        "commonAnnotations": {"summary": "High HTTP 5xx rate"},
        "externalURL": "https://alertmanager.example",
        "alerts": [
            {
                "status": "firing",
                "labels": {
                    "alertname": "HighErrorRate",
                    "service": "payment-api",
                    "severity": "critical",
                },
                "annotations": {
                    "summary": "High HTTP 5xx rate",
                    "description": "More than 5% requests are failing",
                },
                "startsAt": "2026-09-19T08:10:00Z",
                "endsAt": "2026-09-19T08:20:00Z",
                "generatorURL": "https://prometheus.example/graph",
                "fingerprint": "abc123",
            }
        ],
    }


def test_native_alertmanager_v4_model_accepts_camel_case_contract():
    model = AlertmanagerWebhookPayload.model_validate(_payload())
    dumped = model.model_dump(mode="json", by_alias=True)
    assert dumped["groupKey"] == "{}:{alertname=\"HighErrorRate\"}"
    assert dumped["truncatedAlerts"] == 0
    assert dumped["alerts"][0]["startsAt"] == "2026-09-19T08:10:00Z"


def test_firing_alert_becomes_first_class_alert_evidence():
    payload = _payload()
    alert = payload["alerts"][0]
    signal = _signal_from_alert(alert, payload)
    evidence = signal.to_evidence()

    assert signal.source == "prometheus"
    assert signal.source_id == "abc123"
    assert signal.service == "payment-api"
    assert signal.signal_type == "HighErrorRate"
    assert signal.severity == "critical"
    assert signal.timestamp.isoformat() == "2026-09-19T08:10:00+00:00"
    assert evidence["type"] == "alert"
    assert evidence["raw_data"]["prometheus_alert_kind"] == "alertmanager"


def test_missing_fingerprint_uses_stable_identity():
    payload = _payload()
    alert = dict(payload["alerts"][0])
    alert.pop("fingerprint")

    first = _signal_from_alert(alert, payload)
    second = _signal_from_alert(alert, payload)
    assert first.source_id == second.source_id
    assert first.source_id.startswith("prometheus-alert:")


def test_resolved_alert_reuses_problem_fingerprint_and_stable_recovery_id():
    payload = _payload()
    alert = dict(payload["alerts"][0])
    firing = classify_alertmanager_alert(alert, payload)

    alert["status"] = "resolved"
    payload["status"] = "resolved"
    first = classify_alertmanager_alert(alert, payload)
    second = classify_alertmanager_alert(alert, payload)

    assert firing["problem_event_id"] == "abc123"
    assert first["problem_event_id"] == "abc123"
    assert first["recovery_event_id"] == second["recovery_event_id"]
    assert first["recovery_event_id"].startswith("prometheus-recovery:")


def test_per_alert_status_wins_over_group_status():
    payload = _payload()
    payload["status"] = "firing"
    alert = dict(payload["alerts"][0])
    alert["status"] = "resolved"

    identity = classify_alertmanager_alert(alert, payload)
    assert identity["state"] == "resolved"
