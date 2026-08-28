import json

from apps.api.http_logging import _safe_json_body
from domain.contracts.redaction import REDACTED, redact, redact_text


def test_recursive_redaction_covers_required_auth_and_credentials():
    payload = {
        "Authorization": "Bearer top-secret-token",
        "X-API-Key": "key-123",
        "cookie": "session=abc",
        "password": "pw",
        "ssh_credential": "private-value",
        "client_secret": "client-value",
        "database_url": "postgresql://user:pw@db/prod",
        "safe": {"service": "payments"},
    }
    result = redact(payload)
    for key in ("Authorization", "X-API-Key", "cookie", "password", "ssh_credential", "client_secret", "database_url"):
        assert result[key] == REDACTED
    assert result["safe"] == {"service": "payments"}


def test_free_form_redaction_covers_bearer_dsn_and_private_key():
    value = "Bearer abc.def.ghi postgresql://user:pw@db/prod -----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----"
    result = redact_text(value)
    assert "abc.def.ghi" not in result
    assert "user:pw" not in result
    assert "BEGIN PRIVATE KEY" not in result


def test_safe_json_body_redacts_nested_values():
    raw = json.dumps({"nested": {"token": "secret", "value": 3}}).encode()
    result = _safe_json_body(raw, "application/json", enabled=True)
    assert result["nested"]["token"] == REDACTED
    assert result["nested"]["value"] == 3


def test_safe_json_body_omits_non_json():
    result = _safe_json_body(b"password=secret", "application/x-www-form-urlencoded", enabled=True)
    assert result["omitted"] == "non_json_body"
