"""Real ingress payload provenance, redaction, read-only API and UI wiring."""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from fastapi.testclient import TestClient

from apps.api.main import app
from apps.received_signal_view import project_received_signal
from apps.signal_gateway.received_signal import (
    MAX_RECEIVED_SIGNAL_BYTES,
    capture_received_signal,
)
from domain.contracts.redaction import REDACTED


def record(source, raw, ref="e-1"):
    return {
        "id": str(uuid4()),
        "source": source,
        "reference": ref,
        "created_at": datetime(2026, 10, 12, 7, 0, tzinfo=timezone.utc),
        "raw_data": raw,
    }


def test_exact_source_zabbix_fields_tags_and_secret_values_redacted():
    incoming = {
        "eventid": "7200", "name": "TCP port 86 down",
        "message": "Original monitoring alert line\nHost NeoBank",
        "tags": [
            {"tag": "service", "value": "gfpapi"},
            {"tag": "target_port", "value": "86"},
            {"tag": "API-KEY", "value": "do-not-leak"},
        ],
        "password": "must-be-removed",
    }
    stored = capture_received_signal(incoming)
    assert stored["eventid"] == "7200"
    assert stored["message"] == incoming["message"]
    assert stored["tags"][0]["value"] == "gfpapi"
    assert stored["tags"][1]["value"] == "86"
    assert stored["tags"][2]["value"] == REDACTED
    assert stored["password"] == REDACTED
    result = project_received_signal(
        record("zabbix", {
            "signal_type": "port_down",
            "signal_summary": "TCP port 86 down",
            "_received_payload": stored,
            "tags": [{"tag": "service", "value": "gfpapi"}],
        }, ref="7200")
    )
    assert result["source"] == "zabbix"
    assert result["message"] == incoming["message"]
    assert result["payload"]["tags"][0]["value"] == "gfpapi"
    assert result["capture_kind"] == "received_redacted"
    assert result["wire_exact"] is False
    assert result["source_id"] == "7200"
    assert "do-not-leak" not in str(result)
    assert "must-be-removed" not in str(result)


def test_old_zabbix_incident_honestly_labeled_as_normalized():
    result = project_received_signal(record("zabbix", {
        "signal_type": "port_down",
        "signal_summary": "TCP 86 is down",
        "tags": [{"tag": "service", "value": "nginx"}],
        "eventid": "old-id",
    }))
    assert result["capture_kind"] == "normalized_stored"
    assert result["wire_exact"] is False
    assert result["payload"]["tags"][0]["value"] == "nginx"


def test_prometheus_labels_annotations_and_recovery_are_not_lost():
    alert = {
        "status": "resolved",
        "labels": {"alertname": "InstanceDown", "job": "api", "severity": "critical"},
        "annotations": {"summary": "Host down", "description": "HTTP 5xx increased"},
        "fingerprint": "fingerprint-123",
        "endsAt": "2026-10-12T07:02:00Z",
    }
    result = project_received_signal(record("prometheus", {
        "prometheus_alert_kind": "alertmanager_recovery",
        "_received_payload": capture_received_signal(alert),
    }, "prometheus-recovery:fingerprint-123"))
    assert result["lifecycle"] == "recovery"
    assert result["message"] == "HTTP 5xx increased"
    assert result["payload"]["labels"]["alertname"] == "InstanceDown"
    assert result["payload"]["annotations"]["summary"] == "Host down"


def test_elastic_rule_tags_anomaly_payload_preserved():
    incoming = {
        "rule": {"name": "ML anomaly", "tags": ["service:payments", "environment:prod"]},
        "alert": {"id": "elk-alert-9"},
        "anomaly": {"score": 89, "message": "Unexpected request spike"},
    }
    result = project_received_signal(record("elasticsearch", {
        "elastic_alert_kind": "ml_anomaly",
        "signal_type": "ml_anomaly",
        "_received_payload": capture_received_signal(incoming),
    }))
    assert result["source_name"] == "Elasticsearch / ELK"
    assert result["message"] == "Unexpected request spike"
    assert result["payload"]["rule"]["tags"][0] == "service:payments"


def test_secret_bearing_labels_and_untrusted_text_are_redacted():
    incoming = {
        "labels": {"service": "nginx", "authorization": "Bearer supersecret"},
        "annotations": {"description": "token=do-not-leak"},
    }
    result = project_received_signal(record("prometheus", {
        "signal_type": "alert",
        "_received_payload": capture_received_signal(incoming),
    }))
    assert result["payload"]["labels"]["authorization"] == REDACTED
    assert "do-not-leak" not in str(result)
    assert result["message"].startswith("token=")
    assert REDACTED in result["message"]


def test_nonsignal_evidence_is_not_presented_as_ingress_notification():
    assert project_received_signal(record("zabbix", {
        "diagnostic": "get_host", "result": {"items": []}
    })) is None
    assert project_received_signal(record("prometheus", {
        "status": "queried", "result_count": 7
    })) is None
    assert project_received_signal(record("vm_mcp", {
        "signal_type": "invented_by_agent"
    })) is None


def test_original_payload_size_budget_has_no_false_original_claim():
    assert capture_received_signal({"message": "a" * (MAX_RECEIVED_SIGNAL_BYTES + 1)}) is None
    assert capture_received_signal({"message": "normal"}) == {"message": "normal"}


def test_readonly_api_requires_incident_access_and_page_has_real_source_tab():
    target = "/api/v1/incidents/{incident_id}/received-signals"
    routes = [r for r in app.routes if getattr(r, "path", "") == target]
    assert len(routes) == 1
    assert routes[0].methods == {"GET"}
    response = TestClient(app).get(
        "/api/v1/incidents/11111111-1111-4111-8111-111111111111/received-signals"
    )
    assert response.status_code == 401
    source = Path("apps/api/incident_resources.py").read_text(encoding="utf-8")
    assert 'dependencies=[Depends(require_permission("read:incident"))]' in source
    assert "project_received_signal" in source
    assert "select(Evidence)" in source
    html = Path("dashboards/incident-command-room.html").read_text(encoding="utf-8")
    js = Path("dashboards/incident-command-room.js").read_text(encoding="utf-8")
    assert 'href="#ic-received"' in html
    assert 'id="ic-received-signals"' in html
    assert "received-signals?limit=100" in js
    assert "renderReceivedSignals()" in js
    assert "receivedOriginal" in js and "receivedNormalized" in js
    assert "data-copy-received" in js
    assert "JSON.stringify(payload,null,2)" in js
    assert "href="#ic-review"" in html
