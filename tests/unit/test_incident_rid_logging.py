import json
import logging
import re
from pathlib import Path
from uuid import uuid4

from domain.contracts import logging as logging_contract
from domain.contracts.config import settings
from domain.contracts.context import (
    clear_incident_context,
    incident_rid,
    set_trace_id,
)


def _configure_json_logging(tmp_path: Path, monkeypatch) -> Path:
    monkeypatch.setattr(settings, "LOG_LEVEL", "INFO")
    monkeypatch.setattr(settings, "LOG_CONSOLE_ENABLED", False)
    monkeypatch.setattr(settings, "LOG_TEXT_FILE_ENABLED", False)
    monkeypatch.setattr(settings, "LOG_JSON_FILE_ENABLED", True)
    monkeypatch.setattr(settings, "LOG_DIR", str(tmp_path))
    monkeypatch.setattr(settings, "LOG_JSON_FILE", "rid.json.log")
    monkeypatch.setattr(settings, "LOG_ROTATION_MODE", "size")
    monkeypatch.setattr(settings, "LOG_MAX_BYTES", 10_000_000)
    monkeypatch.setattr(settings, "LOG_BACKUP_COUNT", 2)
    monkeypatch.setattr(settings, "LOG_UTC", True)
    logging_contract.configure_logging()
    return tmp_path / "rid.json.log"


def test_incident_rid_is_stable_and_uuid_derived():
    incident_id = uuid4()
    expected = f"rid_{incident_id.hex}"
    assert incident_rid(str(incident_id)) == expected
    assert incident_rid(incident_id) == expected
    assert incident_rid(str(incident_id)) == incident_rid(str(incident_id))


def test_non_uuid_legacy_incident_ids_are_stable_and_not_copied_verbatim():
    first = incident_rid("legacy incident / unsafe chars")
    second = incident_rid("legacy incident / unsafe chars")
    assert first == second
    assert first.startswith("rid_")
    assert "legacy" not in first
    assert len(first) == 36


def test_workflow_event_binds_rid_for_follow_up_logs(tmp_path, monkeypatch):
    path = _configure_json_logging(tmp_path, monkeypatch)
    clear_incident_context()
    incident_id = str(uuid4())
    rid = incident_rid(incident_id)

    logging_contract.log_workflow_step(
        incident_id=incident_id,
        stage="triage",
        component="triage_agent",
        action="classify",
    )
    logging_contract.logger.info("follow_up_without_explicit_incident")

    for handler in logging.getLogger().handlers:
        handler.flush()

    items = [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    assert len(items) == 2
    assert items[0]["incident_id"] == incident_id
    assert items[0]["rid"] == rid
    assert items[1]["incident_id"] == incident_id
    assert items[1]["rid"] == rid


def test_correlation_identifiers_follow_level_in_text_and_json_logs(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "LOG_LEVEL", "INFO")
    monkeypatch.setattr(settings, "LOG_CONSOLE_ENABLED", False)
    monkeypatch.setattr(settings, "LOG_TEXT_FILE_ENABLED", True)
    monkeypatch.setattr(settings, "LOG_JSON_FILE_ENABLED", True)
    monkeypatch.setattr(settings, "LOG_DIR", str(tmp_path))
    monkeypatch.setattr(settings, "LOG_TEXT_FILE", "ordered.log")
    monkeypatch.setattr(settings, "LOG_JSON_FILE", "ordered.json.log")
    monkeypatch.setattr(settings, "LOG_ROTATION_MODE", "size")
    monkeypatch.setattr(settings, "LOG_MAX_BYTES", 10_000_000)
    monkeypatch.setattr(settings, "LOG_BACKUP_COUNT", 2)
    monkeypatch.setattr(settings, "LOG_UTC", True)
    logging_contract.configure_logging()

    clear_incident_context()
    incident_id = str(uuid4())
    rid = incident_rid(incident_id)
    set_trace_id("trc-order-test")
    logging_contract.logger.info(
        "ordered_fields",
        incident_id=incident_id,
        correlation_id="corr-order-test",
    )

    for handler in logging.getLogger().handlers:
        handler.flush()

    text_line = (tmp_path / "ordered.log").read_text(encoding="utf-8").strip()
    level_match = re.search(r"\[info\s*\]", text_line)
    assert level_match is not None
    rid_pos = text_line.index(f"rid={rid}")
    correlation_pos = text_line.index("correlation_id=corr-order-test")
    trace_pos = text_line.index("trace_id=trc-order-test")
    event_pos = text_line.index("ordered_fields")
    assert level_match.end() < rid_pos < correlation_pos < trace_pos < event_pos

    json_line = (tmp_path / "ordered.json.log").read_text(encoding="utf-8").strip()
    assert json_line.index('"level"') < json_line.index('"rid"')
    assert json_line.index('"rid"') < json_line.index('"correlation_id"')
    assert json_line.index('"correlation_id"') < json_line.index('"trace_id"')
    assert json_line.index('"trace_id"') < json_line.index('"event"')
    item = json.loads(json_line)
    assert item["rid"] == rid
    assert item["correlation_id"] == "corr-order-test"
    assert item["trace_id"] == "trc-order-test"
    set_trace_id("")
    clear_incident_context()


def test_hourly_logrotate_policy_and_timer_are_tracked():
    policy = Path("deployment/logrotate/aiops-platform").read_text(encoding="utf-8")
    timer = Path("deployment/systemd/aiops-logrotate.timer").read_text(encoding="utf-8")
    service = Path("deployment/systemd/aiops-logrotate.service").read_text(encoding="utf-8")

    assert "/var/log/aiops/aiops.log" in policy
    assert "/var/log/aiops/aiops.json.log" in policy
    assert "hourly" in policy
    assert "rotate 168" in policy
    assert "compress" in policy
    assert "copytruncate" in policy
    assert "OnCalendar=hourly" in timer
    assert "Persistent=true" in timer
    assert "/usr/sbin/logrotate" in service
    assert "/etc/logrotate.d/aiops-platform" in service


def test_trace_script_accepts_incident_uuid_or_rid_contract():
    text = Path("scripts/trace_incident_logs.py").read_text(encoding="utf-8")
    assert "incident_rid" in text
    assert "aiops*.log*" in text
    assert "gzip.open" in text
