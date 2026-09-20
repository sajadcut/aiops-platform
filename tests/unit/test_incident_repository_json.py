from datetime import date, datetime, time, timezone
from decimal import Decimal
from enum import Enum
from uuid import uuid4

from apps.incident_service.repository import _json_safe


class _SampleState(str, Enum):
    ACTIVE = "active"


def test_json_safe_normalizes_durable_operational_context():
    incident_id = uuid4()
    timestamp = datetime(2026, 9, 20, 9, 54, 3, tzinfo=timezone.utc)
    payload = {
        "timestamp": timestamp,
        "date": date(2026, 9, 20),
        "time": time(9, 54, 3),
        "incident_id": incident_id,
        "state": _SampleState.ACTIVE,
        "score": Decimal("0.1043"),
        "nested": [{"seen_at": timestamp}],
    }

    normalized = _json_safe(payload)

    assert normalized["timestamp"] == "2026-09-20T09:54:03+00:00"
    assert normalized["date"] == "2026-09-20"
    assert normalized["time"] == "09:54:03"
    assert normalized["incident_id"] == str(incident_id)
    assert normalized["state"] == "active"
    assert normalized["score"] == 0.1043
    assert normalized["nested"][0]["seen_at"] == "2026-09-20T09:54:03+00:00"
