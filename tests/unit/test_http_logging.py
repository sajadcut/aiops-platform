from __future__ import annotations

import json

import pytest

from domain.contracts.http_logging import (
    RequestResponseLoggingMiddleware,
    _decode_body,
    sanitize,
    sanitize_headers,
    sanitize_query_string,
)


def test_recursive_redaction_hides_sensitive_fields_and_bearer_tokens():
    value = sanitize({
        "username": "alice",
        "password": "secret-value",
        "nested": {"api_key": "abc", "note": "Bearer raw-token.123"},
    })
    assert value["username"] == "alice"
    assert value["password"] == "[REDACTED]"
    assert value["nested"]["api_key"] == "[REDACTED]"
    assert value["nested"]["note"] == "Bearer [REDACTED]"


def test_headers_and_query_redact_credentials():
    headers = sanitize_headers([
        (b"authorization", b"Bearer abc.def"),
        (b"x-api-key", b"raw-key"),
        (b"content-type", b"application/json"),
    ])
    assert headers["authorization"] == "[REDACTED]"
    assert headers["x-api-key"] == "[REDACTED]"
    assert headers["content-type"] == "application/json"
    query = sanitize_query_string(b"service=haproxy&token=abc&password=def")
    assert "haproxy" in query
    assert "abc" not in query
    assert "def" not in query


def test_form_urlencoded_body_redacts_sensitive_fields():
    value = _decode_body(
        b"username=alice&password=super-secret&token=raw-token&service=haproxy",
        "application/x-www-form-urlencoded",
        False,
    )
    assert value["username"] == "alice"
    assert value["service"] == "haproxy"
    assert value["password"] == "[REDACTED]"
    assert value["token"] == "[REDACTED]"
    assert "super-secret" not in json.dumps(value)
    assert "raw-token" not in json.dumps(value)


@pytest.mark.asyncio
async def test_middleware_preserves_body_and_adds_request_id(monkeypatch):
    captured = []

    class FakeLogger:
        def info(self, event, **kwargs):
            captured.append((event, kwargs))

    import domain.contracts.http_logging as module
    monkeypatch.setattr(module, "logger", FakeLogger())

    async def app(scope, receive, send):
        request = await receive()
        body = request.get("body", b"")
        await send({
            "type": "http.response.start",
            "status": 200,
            "headers": [(b"content-type", b"application/json")],
        })
        await send({
            "type": "http.response.body",
            "body": body,
            "more_body": False,
        })

    middleware = RequestResponseLoggingMiddleware(app, enabled=True, body_max_bytes=4096, log_headers=True)
    sent = []
    received = False

    async def receive():
        nonlocal received
        if received:
            return {"type": "http.request", "body": b"", "more_body": False}
        received = True
        return {
            "type": "http.request",
            "body": json.dumps({"approval_id": "a-1", "password": "hidden"}).encode(),
            "more_body": False,
        }

    async def send(message):
        sent.append(message)

    await middleware(
        {
            "type": "http",
            "method": "POST",
            "path": "/api/v1/execute",
            "query_string": b"",
            "headers": [
                (b"content-type", b"application/json"),
                (b"authorization", b"Bearer never-log-me"),
                (b"x-request-id", b"req-123"),
            ],
        },
        receive,
        send,
    )

    start = next(message for message in sent if message["type"] == "http.response.start")
    assert (b"x-request-id", b"req-123") in start["headers"]
    assert captured
    event, fields = captured[0]
    assert event == "http_request_completed"
    assert fields["request_id"] == "req-123"
    assert fields["approval_id"] == "a-1"
    assert fields["request_headers"]["authorization"] == "[REDACTED]"
    assert fields["request_body"]["password"] == "[REDACTED]"
    assert fields["response_body"]["password"] == "[REDACTED]"
