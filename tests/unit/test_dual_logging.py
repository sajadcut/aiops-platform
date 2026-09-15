import json
import logging
from logging.handlers import RotatingFileHandler, TimedRotatingFileHandler
from pathlib import Path

from domain.contracts import logging as logging_contract
from domain.contracts.config import settings


def _flush_root_handlers() -> None:
    for handler in logging.getLogger().handlers:
        handler.flush()


def _configure_file_logging(tmp_path, monkeypatch, *, text_file="test.log", json_file="test.json.log", rotation="size"):
    monkeypatch.setattr(settings, "LOG_LEVEL", "INFO")
    monkeypatch.setattr(settings, "LOG_CONSOLE_ENABLED", False)
    monkeypatch.setattr(settings, "LOG_TEXT_FILE_ENABLED", True)
    monkeypatch.setattr(settings, "LOG_JSON_FILE_ENABLED", True)
    monkeypatch.setattr(settings, "LOG_DIR", str(tmp_path))
    monkeypatch.setattr(settings, "LOG_TEXT_FILE", text_file)
    monkeypatch.setattr(settings, "LOG_JSON_FILE", json_file)
    monkeypatch.setattr(settings, "LOG_ROTATION_MODE", rotation)
    monkeypatch.setattr(settings, "LOG_MAX_BYTES", 4096)
    monkeypatch.setattr(settings, "LOG_BACKUP_COUNT", 3)
    monkeypatch.setattr(settings, "LOG_ROTATION_WHEN", "midnight")
    monkeypatch.setattr(settings, "LOG_ROTATION_INTERVAL", 1)
    monkeypatch.setattr(settings, "LOG_UTC", True)
    logging_contract.configure_logging()


def test_dual_format_logging_writes_human_and_json_files(tmp_path, monkeypatch):
    _configure_file_logging(tmp_path, monkeypatch)
    logging_contract.logger.info("dual-log-test", incident_id="inc-123", source="unit")
    _flush_root_handlers()

    human_path = Path(tmp_path) / "test.log"
    json_path = Path(tmp_path) / "test.json.log"
    assert human_path.exists()
    assert json_path.exists()
    assert "dual-log-test" in human_path.read_text(encoding="utf-8")

    payload = json.loads(json_path.read_text(encoding="utf-8").strip().splitlines()[-1])
    assert payload["event"] == "dual-log-test"
    assert payload["incident_id"] == "inc-123"
    assert payload["source"] == "unit"
    assert payload["level"] == "info"

    file_handlers = [h for h in logging.getLogger().handlers if isinstance(h, RotatingFileHandler)]
    assert len(file_handlers) == 2


def test_workflow_step_is_written_to_both_files_and_redacts_secrets(tmp_path, monkeypatch):
    _configure_file_logging(tmp_path, monkeypatch, text_file="timeline.log", json_file="timeline.json.log")

    logging_contract.log_workflow_step(
        incident_id="inc-456",
        stage="knowledge_rag",
        component="cognia_rag",
        action="search_completed",
        status="completed",
        summary="Cognia Knowledge RAG returned 2 result(s)",
        details={
            "result_count": 2,
            "source_ids": ["cognia:1:2:3:4"],
            "authorization": "Bearer super-secret-token",
        },
    )
    _flush_root_handlers()

    human_text = (Path(tmp_path) / "timeline.log").read_text(encoding="utf-8")
    assert "workflow_step" in human_text
    assert "knowledge_rag" in human_text
    assert "cognia_rag" in human_text
    assert "super-secret-token" not in human_text

    payload = json.loads((Path(tmp_path) / "timeline.json.log").read_text(encoding="utf-8").strip().splitlines()[-1])
    assert payload["event"] == "workflow_step"
    assert payload["log_type"] == "incident_timeline"
    assert payload["incident_id"] == "inc-456"
    assert payload["stage"] == "knowledge_rag"
    assert payload["component"] == "cognia_rag"
    assert payload["action"] == "search_completed"
    assert payload["status"] == "completed"
    assert payload["details"]["result_count"] == 2
    assert payload["details"]["authorization"] == "[REDACTED]"


def test_time_rotation_uses_timed_handlers(tmp_path, monkeypatch):
    _configure_file_logging(tmp_path, monkeypatch, text_file="time.log", json_file="time.json.log", rotation="time")
    timed = [h for h in logging.getLogger().handlers if isinstance(h, TimedRotatingFileHandler)]
    assert len(timed) == 2
    assert all(h.backupCount == 3 for h in timed)
