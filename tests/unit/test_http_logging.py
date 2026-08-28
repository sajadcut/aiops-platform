import json
import logging

from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

from domain.contracts import logging as logging_contract
from domain.contracts.config import settings
from domain.contracts.http_logging import RequestLoggingMiddleware


def _configure_json_logging(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "LOG_LEVEL", "INFO")
    monkeypatch.setattr(settings, "LOG_CONSOLE_ENABLED", False)
    monkeypatch.setattr(settings, "LOG_TEXT_FILE_ENABLED", False)
    monkeypatch.setattr(settings, "LOG_JSON_FILE_ENABLED", True)
    monkeypatch.setattr(settings, "LOG_DIR", str(tmp_path))
    monkeypatch.setattr(settings, "LOG_JSON_FILE", "http.json.log")
    monkeypatch.setattr(settings, "LOG_ROTATION_MODE", "size")
    monkeypatch.setattr(settings, "LOG_MAX_BYTES", 65536)
    monkeypatch.setattr(settings, "LOG_BACKUP_COUNT", 1)
    monkeypatch.setattr(settings, "LOG_ROTATION_WHEN", "midnight")
    monkeypatch.setattr(settings, "LOG_ROTATION_INTERVAL", 1)
    monkeypatch.setattr(settings, "LOG_UTC", True)
    monkeypatch.setattr(settings, "LOG_HTTP_BODY_ENABLED", True)
    monkeypatch.setattr(settings, "LOG_HTTP_BODY_MAX_BYTES", 4096)
    logging_contract.configure_logging()


def test_http_logging_captures_correlation_context_and_redacts(tmp_path, monkeypatch):
    _configure_json_logging(tmp_path, monkeypatch)
    app = FastAPI()
    app.add_middleware(RequestLoggingMiddleware)

    @app.post("/execute/{incident_id}")
    async def execute(incident_id: str, request: Request):
        request.state.identity_subject = "operator-1"
        request.state.identity_roles = ["sre"]
        return {
            "incident_id": incident_id,
            "approval_id": "approval-1",
            "execution_id": "execution-1",
            "secret": "server-secret-value",
        }

    with TestClient(app) as client:
        response = client.post(
            "/execute/incident-1",
            headers={
                "X-Request-ID": "req-123",
                "X-Correlation-ID": "corr-123",
                "Authorization": "Bearer should-never-appear",
            },
            json={
                "tool_name": "ssh_vm",
                "action": "restart_service",
                "target": "vm01",
                "password": "client-secret-value",
            },
        )

    for handler in logging.getLogger().handlers:
        handler.flush()
    payload = json.loads((tmp_path / "http.json.log").read_text(encoding="utf-8").strip().splitlines()[-1])

    assert response.status_code == 200
    assert response.headers["x-request-id"] == "req-123"
    assert response.headers["x-correlation-id"] == "corr-123"
    assert payload["event"] == "http_request_completed"
    assert payload["request_id"] == "req-123"
    assert payload["correlation_id"] == "corr-123"
    assert payload["method"] == "POST"
    assert payload["path"] == "/execute/incident-1"
    assert payload["status"] == 200
    assert payload["identity"] == "operator-1"
    assert payload["incident_id"] == "incident-1"
    assert payload["approval_id"] == "approval-1"
    assert payload["execution_id"] == "execution-1"
    assert payload["tool"] == "ssh_vm"
    assert payload["action"] == "restart_service"
    assert payload["target"] == "vm01"
    serialized = json.dumps(payload)
    assert "client-secret-value" not in serialized
    assert "server-secret-value" not in serialized
    assert "should-never-appear" not in serialized
    assert payload["request_body"]["password"] == "[REDACTED]"
    assert payload["response_body"]["secret"] == "[REDACTED]"


def test_redactor_sanitizes_database_and_bearer_credentials():
    value = logging_contract.redact_value(
        {
            "database_url": "postgresql://user:password@db/aiops",
            "message": "Authorization failed: Bearer abc.def.ghi",
            "nested": {"x-api-key": "sensitive-key"},
        }
    )
    serialized = json.dumps(value)
    assert "password@" not in serialized
    assert "abc.def.ghi" not in serialized
    assert "sensitive-key" not in serialized
