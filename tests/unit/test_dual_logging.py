import json
import logging
from logging.handlers import RotatingFileHandler, TimedRotatingFileHandler
from pathlib import Path

from domain.contracts import logging as logging_contract
from domain.contracts.config import settings


def _flush_root_handlers() -> None:
    for handler in logging.getLogger().handlers:
        handler.flush()


def test_dual_format_logging_writes_human_and_json_files(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "LOG_LEVEL", "INFO")
    monkeypatch.setattr(settings, "LOG_CONSOLE_ENABLED", False)
    monkeypatch.setattr(settings, "LOG_TEXT_FILE_ENABLED", True)
    monkeypatch.setattr(settings, "LOG_JSON_FILE_ENABLED", True)
    monkeypatch.setattr(settings, "LOG_DIR", str(tmp_path))
    monkeypatch.setattr(settings, "LOG_TEXT_FILE", "test.log")
    monkeypatch.setattr(settings, "LOG_JSON_FILE", "test.json.log")
    monkeypatch.setattr(settings, "LOG_ROTATION_MODE", "size")
    monkeypatch.setattr(settings, "LOG_MAX_BYTES", 4096)
    monkeypatch.setattr(settings, "LOG_BACKUP_COUNT", 2)
    monkeypatch.setattr(settings, "LOG_ROTATION_WHEN", "midnight")
    monkeypatch.setattr(settings, "LOG_ROTATION_INTERVAL", 1)
    monkeypatch.setattr(settings, "LOG_UTC", True)

    logging_contract.configure_logging()
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


def test_time_rotation_uses_timed_handlers(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "LOG_LEVEL", "INFO")
    monkeypatch.setattr(settings, "LOG_CONSOLE_ENABLED", False)
    monkeypatch.setattr(settings, "LOG_TEXT_FILE_ENABLED", True)
    monkeypatch.setattr(settings, "LOG_JSON_FILE_ENABLED", True)
    monkeypatch.setattr(settings, "LOG_DIR", str(tmp_path))
    monkeypatch.setattr(settings, "LOG_TEXT_FILE", "time.log")
    monkeypatch.setattr(settings, "LOG_JSON_FILE", "time.json.log")
    monkeypatch.setattr(settings, "LOG_ROTATION_MODE", "time")
    monkeypatch.setattr(settings, "LOG_MAX_BYTES", 4096)
    monkeypatch.setattr(settings, "LOG_BACKUP_COUNT", 3)
    monkeypatch.setattr(settings, "LOG_ROTATION_WHEN", "midnight")
    monkeypatch.setattr(settings, "LOG_ROTATION_INTERVAL", 1)
    monkeypatch.setattr(settings, "LOG_UTC", True)

    logging_contract.configure_logging()
    timed = [h for h in logging.getLogger().handlers if isinstance(h, TimedRotatingFileHandler)]
    assert len(timed) == 2
    assert all(h.backupCount == 3 for h in timed)
