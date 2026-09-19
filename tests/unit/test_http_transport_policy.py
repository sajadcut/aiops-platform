import asyncio
from pathlib import Path
import ssl

import httpx
import pytest

import integrations.http_transport as http_transport
from integrations.http_transport import insecure_async_client, insecure_ssl_context, insecure_sync_client


def test_transport_factories_always_disable_tls_certificate_validation(monkeypatch):
    captured = []

    class FakeAsync:
        def __init__(self, **kwargs):
            captured.append(("async", kwargs))

    class FakeSync:
        def __init__(self, **kwargs):
            captured.append(("sync", kwargs))

    monkeypatch.setattr(httpx, "AsyncClient", FakeAsync)
    monkeypatch.setattr(httpx, "Client", FakeSync)

    insecure_async_client(timeout=1, verify=True, component="llm:test")
    insecure_sync_client(timeout=1, verify=True, component="ops:test")

    assert captured[0][1]["verify"] is False
    assert captured[1][1]["verify"] is False
    assert "component" not in captured[0][1]
    assert "component" not in captured[1][1]


def test_insecure_ssl_context_disables_certificate_and_hostname_validation():
    context = insecure_ssl_context()
    assert context.check_hostname is False
    assert context.verify_mode == ssl.CERT_NONE


def test_oidc_jwks_client_receives_insecure_ssl_context():
    source = Path("apps/security/token_validator.py").read_text(encoding="utf-8")
    assert "PyJWKClient(jwks_url, ssl_context=insecure_ssl_context())" in source
    # Transport trust is disabled, but JWT cryptographic verification stays enabled.
    assert "jwt.decode(" in source
    assert 'algorithms=["RS256", "RS384", "RS512", "ES256", "ES384", "ES512"]' in source


def test_no_https_enforcement_or_server_ca_config_remains_in_runtime_contract():
    banned = {
        "MCP_REQUIRE_HTTPS",
        "A2A_REQUIRE_HTTPS",
        "COGNIA_TLS_VERIFY",
        "MCP_CA_CERT_PATH",
        "KUBERNETES_CA_CERT_PATH",
        "AIOPS_TLS_VERIFY",
        "mcp_https_required",
        "a2a_https_required",
    }
    roots = [Path("apps"), Path("agents"), Path("domain"), Path("integrations"), Path("knowledge")]
    sources = [Path(".env.example"), Path("operational.env.example")]
    for root in roots:
        sources.extend(root.rglob("*.py"))
    for path in sources:
        text = path.read_text(encoding="utf-8")
        found = sorted(token for token in banned if token in text)
        assert not found, f"{path} still contains obsolete HTTPS/certificate policy: {found}"


def test_outbound_runtime_httpx_clients_use_central_insecure_transport_factory():
    roots = [Path("apps"), Path("agents"), Path("integrations"), Path("knowledge")]
    offenders = []
    for root in roots:
        for path in root.rglob("*.py"):
            if path.as_posix() == "integrations/http_transport.py":
                continue
            text = path.read_text(encoding="utf-8")
            if "httpx.AsyncClient(" in text or "httpx.Client(" in text:
                offenders.append(path.as_posix())
    assert not offenders, f"direct httpx clients bypass transport policy: {offenders}"



class _LogRecorder:
    def __init__(self):
        self.events = []

    def info(self, event, **fields):
        self.events.append(("info", event, fields))

    def warning(self, event, **fields):
        self.events.append(("warning", event, fields))


def test_async_transport_logs_success_latency_without_query_or_secret(monkeypatch):
    recorder = _LogRecorder()
    monkeypatch.setattr(http_transport, "logger", recorder)

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"ok": True}, request=request)

    async def run():
        async with insecure_async_client(
            base_url="https://example.test",
            transport=httpx.MockTransport(handler),
            component="llm:test-provider",
        ) as client:
            response = await client.get("/v1/chat/completions?api_key=super-secret")
            assert response.status_code == 200

    asyncio.run(run())

    level, event, fields = recorder.events[-1]
    assert level == "info"
    assert event == "outbound_http_completed"
    assert fields["component"] == "llm:test-provider"
    assert fields["method"] == "GET"
    assert fields["host"] == "example.test"
    assert fields["path"] == "/v1/chat/completions"
    assert fields["status_code"] == 200
    assert fields["duration_ms"] >= 0
    assert "super-secret" not in str(fields)
    assert "api_key" not in str(fields)


def test_async_transport_logs_failure_latency_and_error_type(monkeypatch):
    recorder = _LogRecorder()
    monkeypatch.setattr(http_transport, "logger", recorder)

    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection failed", request=request)

    async def run():
        async with insecure_async_client(
            transport=httpx.MockTransport(handler),
            component="mcp:zabbix",
        ) as client:
            with pytest.raises(httpx.ConnectError):
                await client.post("http://10.0.0.10:5080/mcp?token=do-not-log", json={"jsonrpc": "2.0"})

    asyncio.run(run())

    level, event, fields = recorder.events[-1]
    assert level == "warning"
    assert event == "outbound_http_failed"
    assert fields["component"] == "mcp:zabbix"
    assert fields["method"] == "POST"
    assert fields["host"] == "10.0.0.10"
    assert fields["port"] == 5080
    assert fields["path"] == "/mcp"
    assert fields["error_type"] == "ConnectError"
    assert fields["duration_ms"] >= 0
    assert "do-not-log" not in str(fields)


def test_sync_transport_logs_latency(monkeypatch):
    recorder = _LogRecorder()
    monkeypatch.setattr(http_transport, "logger", recorder)

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(204, request=request)

    with insecure_sync_client(
        transport=httpx.MockTransport(handler),
        component="operational-acceptance",
    ) as client:
        response = client.get("http://127.0.0.1:8000/api/v1/health")
        assert response.status_code == 204

    level, event, fields = recorder.events[-1]
    assert level == "info"
    assert event == "outbound_http_completed"
    assert fields["component"] == "operational-acceptance"
    assert fields["duration_ms"] >= 0
