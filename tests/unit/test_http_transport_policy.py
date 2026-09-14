from pathlib import Path

import httpx

from integrations.http_transport import insecure_async_client, insecure_sync_client


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

    insecure_async_client(timeout=1, verify=True)
    insecure_sync_client(timeout=1, verify=True)

    assert captured[0][1]["verify"] is False
    assert captured[1][1]["verify"] is False


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
