"""Operator-only projection of durable ingress evidence.

Only real ingress events are eligible; monitoring/MCP observations and agent
output must not appear as source notifications. Never reconstruct a missing
webhook or claim the post-normalization record is original wire bytes.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any

from domain.contracts.redaction import redact

SOURCE_NAMES = {
    "zabbix": "Zabbix",
    "prometheus": "Prometheus / Alertmanager",
    "elasticsearch": "Elasticsearch / ELK",
    "kubernetes": "Kubernetes",
    "security": "Security",
    "manual": "Manual",
}


def _dict(value: Any) -> dict:
    return value if isinstance(value, dict) else {}


def _as_timestamp(value: Any) -> str | None:
    return value.isoformat() if isinstance(value, datetime) else str(value) if value else None


def project_received_signal(record: dict[str, Any]) -> dict[str, Any] | None:
    source = str(record.get("source") or "").lower()
    raw = _dict(record.get("raw_data"))
    if source not in SOURCE_NAMES:
        return None
    # These markers originate in the ingestion path, unlike incidental
    # diagnostics from integrations/zabbix, elastic and prometheus MCP.
    is_ingress = (
        "signal_type" in raw or "signal_summary" in raw
        or raw.get("zabbix_lifecycle_state") == "recovery"
        or raw.get("prometheus_alert_kind") in {"alertmanager", "alertmanager_recovery"}
        or raw.get("elastic_alert_kind") in {"ml_anomaly", "ml_anomaly_recovery"}
    )
    if not is_ingress:
        return None

    received = raw.get("_received_payload")
    original_captured = isinstance(received, dict)
    # Never return credential-bearing internal fields, even in fallback.
    normalized = {key: value for key, value in raw.items() if key != "_received_payload"}
    payload = redact(received if original_captured else normalized)
    payload = _dict(payload)
    annotations = _dict(payload.get("annotations") or raw.get("annotations"))
    anomaly = _dict(payload.get("anomaly") or raw.get("anomaly"))
    text = (
        payload.get("message")
        or payload.get("name")
        or annotations.get("description")
        or annotations.get("summary")
        or anomaly.get("message")
        or raw.get("signal_summary")
        or record.get("summary")
    )
    if not isinstance(text, str):
        text = str(text) if text is not None else ""
    # A sourced summary is shown as recorded, never reworded by the LLM.
    text = str(redact(text))
    recovery = (
        raw.get("zabbix_lifecycle_state") == "recovery"
        or raw.get("prometheus_alert_kind") == "alertmanager_recovery"
        or raw.get("elastic_alert_kind") == "ml_anomaly_recovery"
    )
    return {
        "source": source,
        "source_name": SOURCE_NAMES[source],
        "source_id": str(redact(record.get("reference") or "")),
        "evidence_id": str(record.get("id") or ""),
        "received_at": _as_timestamp(record.get("created_at")),
        "occurred_at": _as_timestamp(
            payload.get("timestamp") or payload.get("startsAt")
            or anomaly.get("timestamp") or raw.get("timestamp") or raw.get("startsAt")
        ),
        "signal_type": str(redact(raw.get("signal_type") or raw.get("trigger") or "")),
        "message": text,
        "lifecycle": "recovery" if recovery else "problem",
        "capture_kind": "received_redacted" if original_captured else "normalized_stored",
        "wire_exact": False,
        "payload": payload,
    }
