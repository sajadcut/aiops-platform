from __future__ import annotations

from pathlib import Path
import re


def read(path: str) -> str:
    return Path(path).read_text(encoding="utf-8")


def write(path: str, text: str) -> None:
    Path(path).write_text(text, encoding="utf-8")


def replace_once(path: str, old: str, new: str) -> None:
    text = read(path)
    if old not in text:
        raise SystemExit(f"marker not found: {path}: {old[:120]!r}")
    if text.count(old) != 1:
        raise SystemExit(f"marker not unique: {path}: {text.count(old)}")
    write(path, text.replace(old, new, 1))


def remove_line(path: str, exact: str) -> None:
    text = read(path)
    marker = exact + "\n"
    if marker not in text:
        raise SystemExit(f"line not found: {path}: {exact!r}")
    write(path, text.replace(marker, "", 1))


def add_import_after_httpx(path: str, import_line: str) -> None:
    text = read(path)
    if import_line in text:
        return
    if "import httpx\n" not in text:
        raise SystemExit(f"httpx import not found: {path}")
    write(path, text.replace("import httpx\n", f"import httpx\n{import_line}\n", 1))


# One canonical outbound HTTP(S) transport policy. HTTP and HTTPS are both
# supported. HTTPS certificate/hostname validation is intentionally disabled by
# deployment requirement. This does not disable application-level auth, JWT
# signature validation, bearer tokens, RBAC, MCP authorization, or allowlists.
Path("integrations/http_transport.py").write_text(
    '''from __future__ import annotations\n\nfrom typing import Any\n\nimport httpx\n\n\ndef insecure_async_client(**kwargs: Any) -> httpx.AsyncClient:\n    \"\"\"Create an outbound HTTP(S) client with TLS certificate validation disabled.\"\"\"\n    kwargs[\"verify\"] = False\n    return httpx.AsyncClient(**kwargs)  # nosec B501 - explicit project transport policy\n\n\ndef insecure_sync_client(**kwargs: Any) -> httpx.Client:\n    \"\"\"Create a synchronous outbound HTTP(S) client with TLS validation disabled.\"\"\"\n    kwargs[\"verify\"] = False\n    return httpx.Client(**kwargs)  # nosec B501 - explicit project transport policy\n''',
    encoding="utf-8",
)

# Remove obsolete transport-policy configuration switches. There is no runtime
# mode that requires HTTPS or enables certificate verification.
for line in (
    "    COGNIA_TLS_VERIFY: bool = Field(...)",
    "    A2A_REQUIRE_HTTPS: bool = Field(...)",
    "    MCP_REQUIRE_HTTPS: bool = Field(...)",
    "    MCP_CA_CERT_PATH: Optional[str] = Field(...)",
    "    KUBERNETES_CA_CERT_PATH: Optional[str] = Field(...)",
):
    remove_line("domain/contracts/config.py", line)

replace_once(
    "domain/contracts/config.py",
    '''            cognia_scheme = urlparse(str(self.COGNIA_BASE_URL or "")).scheme.lower()\n            if cognia_scheme not in {"http", "https"}:\n                raise ValueError("COGNIA_BASE_URL must use HTTP or HTTPS")\n            if cognia_scheme == "https" and not self.COGNIA_TLS_VERIFY:\n                raise ValueError("COGNIA_TLS_VERIFY must be enabled when Cognia uses HTTPS in production")\n''',
    '''            cognia_scheme = urlparse(str(self.COGNIA_BASE_URL or "")).scheme.lower()\n            if cognia_scheme not in {"http", "https"}:\n                raise ValueError("COGNIA_BASE_URL must use HTTP or HTTPS")\n''',
)

# Tracked config templates no longer expose HTTPS-enforcement or CA-validation
# switches, because certificate verification is always disabled for outbound HTTPS.
env = read(".env.example")
for line in (
    "COGNIA_TLS_VERIFY=True\n",
    "A2A_REQUIRE_HTTPS=True\n",
    "MCP_REQUIRE_HTTPS=False\n",
    "MCP_CA_CERT_PATH=\n",
    "KUBERNETES_CA_CERT_PATH=\n",
):
    if line not in env:
        raise SystemExit(f"env marker missing: {line.strip()}")
    env = env.replace(line, "", 1)
env = env.replace(
    "# COGNIA_BASE_URL supports http:// and https://. When https:// is used in\n# production, COGNIA_TLS_VERIFY must remain enabled.\n",
    "# COGNIA_BASE_URL supports both http:// and https://. HTTPS certificate\n# validation is intentionally disabled by the project transport policy.\n",
)
write(".env.example", env)

operational_env = read("operational.env.example")
if "AIOPS_TLS_VERIFY=" in operational_env:
    operational_env = re.sub(r"^AIOPS_TLS_VERIFY=.*\n", "", operational_env, flags=re.MULTILINE)
write("operational.env.example", operational_env)

# API startup: URLs may be HTTP or HTTPS. Keep authentication/authorization
# checks; remove only HTTPS-only gates.
replace_once(
    "apps/api/main.py",
    '''def _is_https(value: str | None) -> bool:\n    return bool(value and urlparse(str(value)).scheme == "https")\n''',
    '''def _is_http_or_https(value: str | None) -> bool:\n    if not value:\n        return False\n    parsed = urlparse(str(value))\n    return parsed.scheme.lower() in {"http", "https"} and bool(parsed.netloc)\n''',
)
main = read("apps/api/main.py").replace("_is_https(", "_is_http_or_https(")
main = main.replace("must use HTTPS in production", "must use HTTP or HTTPS in production")
main = main.replace(
    '''    if not settings.MCP_REQUIRE_HTTPS:\n        errors.append("MCP_REQUIRE_HTTPS must be enabled in production")\n''',
    "",
)
main = main.replace(
    '''    if settings.A2A_ALLOWED_TARGETS and not settings.A2A_REQUIRE_HTTPS:\n        errors.append("production A2A targets require HTTPS")\n''',
    "",
)
write("apps/api/main.py", main)

# MCP: allow HTTP/HTTPS, never validate server certificates, retain optional
# client certificate/key only as outbound client identity when explicitly used.
add_import_after_httpx("integrations/mcp_client.py", "from integrations.http_transport import insecure_async_client")
mcp = read("integrations/mcp_client.py")
for line in (
    "        ca_cert_path: Optional[str] = None,\n",
    "        require_https: bool = True,\n",
    "        self.require_https = bool(require_https)\n",
):
    if line not in mcp:
        raise SystemExit(f"MCP marker missing: {line.strip()}")
    mcp = mcp.replace(line, "", 1)
mcp = mcp.replace(
    '''        if self.require_https and parsed.scheme != "https":\n            raise ValueError(f"mcp_https_required:{server_name}")\n''',
    "",
)
mcp = mcp.replace(
    '''        verify: bool | str = ca_cert_path or True\n        cert = (client_cert_path, client_key_path) if client_cert_path and client_key_path else None\n        self._client = httpx.AsyncClient(timeout=self.timeout, verify=verify, cert=cert)\n''',
    '''        cert = (client_cert_path, client_key_path) if client_cert_path and client_key_path else None\n        self._client = insecure_async_client(timeout=self.timeout, cert=cert)\n''',
)
write("integrations/mcp_client.py", mcp)

for path in (
    "integrations/vm/mcp_client.py",
    "integrations/zabbix/mcp_client.py",
    "integrations/kubernetes/mcp_client.py",
    "integrations/prometheus/mcp_client.py",
    "integrations/elasticsearch/mcp_client.py",
):
    text = read(path)
    for marker in (
        "            ca_cert_path=settings.MCP_CA_CERT_PATH,\n",
        "            require_https=settings.MCP_REQUIRE_HTTPS,\n",
    ):
        if marker not in text:
            raise SystemExit(f"wrapper marker missing: {path}: {marker.strip()}")
        text = text.replace(marker, "", 1)
    write(path, text)

# A2A: allowlisted origins may be HTTP or HTTPS; HTTPS certificate validation is off.
add_import_after_httpx("agents/shared/a2a_agent.py", "from integrations.http_transport import insecure_async_client")
a2a = read("agents/shared/a2a_agent.py")
a2a = a2a.replace(
    "        self._client = httpx.AsyncClient(timeout=settings.A2A_TIMEOUT_SECONDS)\n",
    "        self._client = insecure_async_client(timeout=settings.A2A_TIMEOUT_SECONDS)\n",
)
a2a = a2a.replace(
    '''        parsed = urlparse(target_url)\n        if settings.A2A_REQUIRE_HTTPS and parsed.scheme.lower() != "https":\n            raise ValueError("a2a_https_required")\n''',
    "",
)
write("agents/shared/a2a_agent.py", a2a)

# Cognia uses the same invariant: HTTP/HTTPS accepted, HTTPS certificate checks off.
add_import_after_httpx("integrations/cognia/client.py", "from integrations.http_transport import insecure_async_client")
cognia = read("integrations/cognia/client.py")
for marker in (
    "        tls_verify: Optional[bool] = None,\n",
    "        self.tls_verify = settings.COGNIA_TLS_VERIFY if tls_verify is None else bool(tls_verify)\n",
):
    if marker not in cognia:
        raise SystemExit(f"Cognia marker missing: {marker.strip()}")
    cognia = cognia.replace(marker, "", 1)
cognia = cognia.replace(
    '''        self._client = httpx.AsyncClient(\n            base_url=self.base_url,\n            timeout=self.timeout_seconds,\n            verify=self.tls_verify,\n            transport=transport,\n            headers={"Accept": "application/json"},\n        )\n''',
    '''        self._client = insecure_async_client(\n            base_url=self.base_url,\n            timeout=self.timeout_seconds,\n            transport=transport,\n            headers={"Accept": "application/json"},\n        )\n''',
)
write("integrations/cognia/client.py", cognia)

# Every other outbound httpx integration uses the same certificate-disabled helper.
async_paths = (
    "apps/security/token_validator.py",
    "integrations/prometheus/client.py",
    "knowledge/__init__.py",
    "integrations/zabbix/connector.py",
    "integrations/elasticsearch/client.py",
    "integrations/llm/openai_compatible.py",
    "integrations/kubernetes/client.py",
)
for path in async_paths:
    add_import_after_httpx(path, "from integrations.http_transport import insecure_async_client")
    text = read(path).replace("httpx.AsyncClient(", "insecure_async_client(")
    write(path, text)

# Direct Kubernetes HTTP client must not consume a CA path or pass a verify policy.
k8s = read("integrations/kubernetes/client.py")
k8s = re.sub(
    r"\n    def _verify\(self\):\n        return settings\.KUBERNETES_CA_CERT_PATH or True\n",
    "",
    k8s,
)
k8s = k8s.replace("            verify=self._verify(),\n", "")
write("integrations/kubernetes/client.py", k8s)

# Operational acceptance follows the same transport behavior.
add_import_after_httpx("tests/operational/run_operational_acceptance.py", "from integrations.http_transport import insecure_sync_client")
ops = read("tests/operational/run_operational_acceptance.py")
ops = ops.replace("httpx.Client(", "insecure_sync_client(")
ops = re.sub(r"\n\s*verify=os\.getenv\(\"AIOPS_TLS_VERIFY\", \"true\"\)\.lower\(\) != \"false\",", "", ops)
write("tests/operational/run_operational_acceptance.py", ops)

# Centralized config tests: both schemes are allowed and no TLS-validation knobs remain.
test_cfg = read("tests/unit/test_centralized_config.py")
test_cfg = test_cfg.replace("                COGNIA_TLS_VERIFY=True,\n", "")
test_cfg = test_cfg.replace("            COGNIA_TLS_VERIFY=True,\n", "")
pattern = re.compile(
    r"def test_production_cognia_supports_http_and_https_transport_contract\(\):\n.*?\n\ndef test_production_cognia_accepts_machine_identity_and_explicit_kbs",
    re.DOTALL,
)
replacement = '''def test_production_cognia_supports_http_and_https_transport_contract():\n    base = _settings_data(\n        APP_ENV="production",\n        COGNIA_CLIENT_ID="app-id",\n        COGNIA_CLIENT_SECRET="test-only-secret",\n        COGNIA_KNOWLEDGE_BASE_IDS=[10],\n    )\n\n    assert Settings(_env_file=None, **{**base, "COGNIA_BASE_URL": "http://cognia.test"}).COGNIA_BASE_URL == "http://cognia.test"\n    assert Settings(_env_file=None, **{**base, "COGNIA_BASE_URL": "https://cognia.test"}).COGNIA_BASE_URL == "https://cognia.test"\n\n    with pytest.raises(ValidationError, match="COGNIA_BASE_URL must use HTTP or HTTPS"):\n        Settings(_env_file=None, **{**base, "COGNIA_BASE_URL": "ftp://cognia.test"})\n\n\ndef test_production_cognia_accepts_machine_identity_and_explicit_kbs'''
test_cfg, count = pattern.subn(replacement, test_cfg, count=1)
if count != 1:
    raise SystemExit("central config transport test block not found")
write("tests/unit/test_centralized_config.py", test_cfg)

# MCP unit contract: HTTP and HTTPS are both valid, invalid schemes remain rejected.
mcp_test = read("tests/unit/test_mcp_external_boundary.py")
mcp_test = mcp_test.replace(", require_https=False", "")
mcp_test = re.sub(
    r"\ndef test_mcp_client_requires_https_when_configured\(\):\n    with pytest\.raises\(ValueError, match=\"mcp_https_required\"\):\n        MCPClient\(\"http://mcp\.test/mcp\", \"test\", allowed_tools=\{\"read_safe\"\}, require_https=True\)\n",
    '''\ndef test_mcp_client_supports_http_and_https():\n    import asyncio\n    http_client = MCPClient("http://mcp.test/mcp", "test-http", allowed_tools={"read_safe"})\n    https_client = MCPClient("https://mcp.test/mcp", "test-https", allowed_tools={"read_safe"})\n    asyncio.run(http_client.close())\n    asyncio.run(https_client.close())\n''',
    mcp_test,
)
write("tests/unit/test_mcp_external_boundary.py", mcp_test)

# A2A unit test: scheme is not an authorization decision; allowlist remains authoritative.
a2a_test = read("tests/unit/test_agent_completion_contract.py")
a2a_test = a2a_test.replace('    monkeypatch.setattr(settings, "A2A_REQUIRE_HTTPS", True)\n', "")
a2a_test = a2a_test.replace(
    '''    with pytest.raises(ValueError, match="a2a_https_required"):\n        await agent.send_request("http://agent.internal/rpc", {})\n''',
    "",
)
write("tests/unit/test_agent_completion_contract.py", a2a_test)

# Kubernetes settings inventory test no longer expects a CA verification setting.
k8s_test = read("tests/unit/test_kubernetes_readonly_evidence.py")
k8s_test = k8s_test.replace('        "KUBERNETES_CA_CERT_PATH",\n', "")
write("tests/unit/test_kubernetes_readonly_evidence.py", k8s_test)

# Regression guard for the explicit project transport requirement.
Path("tests/unit/test_http_transport_policy.py").write_text(
    '''from pathlib import Path\n\nimport httpx\n\nfrom integrations.http_transport import insecure_async_client, insecure_sync_client\n\n\ndef test_transport_factories_always_disable_tls_certificate_validation(monkeypatch):\n    captured = []\n\n    class FakeAsync:\n        def __init__(self, **kwargs):\n            captured.append((\"async\", kwargs))\n\n    class FakeSync:\n        def __init__(self, **kwargs):\n            captured.append((\"sync\", kwargs))\n\n    monkeypatch.setattr(httpx, \"AsyncClient\", FakeAsync)\n    monkeypatch.setattr(httpx, \"Client\", FakeSync)\n\n    insecure_async_client(timeout=1, verify=True)\n    insecure_sync_client(timeout=1, verify=True)\n\n    assert captured[0][1][\"verify\"] is False\n    assert captured[1][1][\"verify\"] is False\n\n\ndef test_no_https_enforcement_or_server_ca_config_remains_in_runtime_contract():\n    banned = {\n        \"MCP_REQUIRE_HTTPS\",\n        \"A2A_REQUIRE_HTTPS\",\n        \"COGNIA_TLS_VERIFY\",\n        \"MCP_CA_CERT_PATH\",\n        \"KUBERNETES_CA_CERT_PATH\",\n        \"AIOPS_TLS_VERIFY\",\n        \"mcp_https_required\",\n        \"a2a_https_required\",\n    }\n    roots = [Path(\"apps\"), Path(\"agents\"), Path(\"domain\"), Path(\"integrations\"), Path(\"knowledge\")]\n    sources = [Path(\".env.example\"), Path(\"operational.env.example\")]\n    for root in roots:\n        sources.extend(root.rglob(\"*.py\"))\n    for path in sources:\n        text = path.read_text(encoding=\"utf-8\")\n        found = sorted(token for token in banned if token in text)\n        assert not found, f\"{path} still contains obsolete HTTPS/certificate policy: {found}\"\n\n\ndef test_outbound_runtime_httpx_clients_use_central_insecure_transport_factory():\n    roots = [Path(\"apps\"), Path(\"agents\"), Path(\"integrations\"), Path(\"knowledge\")]\n    offenders = []\n    for root in roots:\n        for path in root.rglob(\"*.py\"):\n            if path.as_posix() == \"integrations/http_transport.py\":\n                continue\n            text = path.read_text(encoding=\"utf-8\")\n            if \"httpx.AsyncClient(\" in text or \"httpx.Client(\" in text:\n                offenders.append(path.as_posix())\n    assert not offenders, f\"direct httpx clients bypass transport policy: {offenders}\"\n''',
    encoding="utf-8",
)

# Documentation: remove HTTPS-only claims and state the explicit transport policy.
doc_replacements = {
    "docs/CONFIGURATION.md": [
        ("configured OIDC issuer/JWKS endpoints are not HTTPS", "configured OIDC issuer/JWKS endpoints are not HTTP(S)"),
        ("required Zabbix, Elasticsearch or Prometheus MCP URLs are missing/non-HTTPS", "required Zabbix, Elasticsearch or Prometheus MCP URLs are missing/non-HTTP(S)"),
        ("- `MCP_REQUIRE_HTTPS=false`;\n", ""),
        ("`MCP_PROTOCOL_VERSION`, `MCP_REQUIRE_HTTPS`, `MCP_TIMEOUT_SECONDS`", "`MCP_PROTOCOL_VERSION`, `MCP_TIMEOUT_SECONDS`"),
        ("Production requires HTTPS; invalid timeout fails production validation.", "HTTP and HTTPS are supported; invalid timeout fails production validation. HTTPS server certificates are not validated by project policy."),
        ("`MCP_CA_CERT_PATH`, `MCP_CLIENT_CERT_PATH`, `MCP_CLIENT_KEY_PATH`", "`MCP_CLIENT_CERT_PATH`, `MCP_CLIENT_KEY_PATH`"),
        ("cert/key must be configured together; mounts are deployment responsibility.", "optional client cert/key must be configured together when used for client identity; server certificates are not validated."),
        ("`A2A_TIMEOUT_SECONDS`, `A2A_ALLOWED_TARGETS`, `A2A_REQUIRE_HTTPS`", "`A2A_TIMEOUT_SECONDS`, `A2A_ALLOWED_TARGETS`"),
        ("Timeout positive; configured production targets require HTTPS.", "Timeout positive; allowlisted targets may use HTTP or HTTPS. HTTPS server certificates are not validated."),
        ("issuer/JWKS must use HTTPS in production.", "issuer/JWKS may use HTTP or HTTPS; JWT signatures are still validated while HTTPS server certificates are not."),
        ("`KUBERNETES_API_URL`, `KUBERNETES_TOKEN`, `KUBERNETES_TOKEN_FILE`, `KUBERNETES_CA_CERT_PATH`, `KUBERNETES_NAMESPACE`, `KUBERNETES_TIMEOUT_SECONDS`, `KUBERNETES_LOG_TAIL_LINES`", "`KUBERNETES_API_URL`, `KUBERNETES_TOKEN`, `KUBERNETES_TOKEN_FILE`, `KUBERNETES_NAMESPACE`, `KUBERNETES_TIMEOUT_SECONDS`, `KUBERNETES_LOG_TAIL_LINES`"),
        ("HTTP MCP URLs are acceptable only because `APP_ENV=development`; governed production startup rejects them where applicable.", "HTTP and HTTPS integration URLs are both supported in every environment; HTTPS certificate verification is intentionally disabled by project policy."),
    ],
    "docs/DEPLOYMENT.md": [("MCP_REQUIRE_HTTPS=true\n", "")],
    "agents/README.md": [("allowlist and HTTPS policy", "allowlist and HTTP(S) scheme policy")],
    "docs/adr/DECISIONS.md": [("**Production remote MCP requirements:** HTTPS،", "**Production remote MCP requirements:** HTTP/HTTPS transport،")],
    "docs/BENCHMARK_2026.md": [("HTTPS/allowlist exists", "HTTP(S)/allowlist exists")],
}
for path, replacements in doc_replacements.items():
    text = read(path)
    for old, new in replacements:
        if old in text:
            text = text.replace(old, new)
    write(path, text)

# Authoritative docs: make the changed trust model explicit.
for path in (
    "MASTER.md",
    "README.md",
    "FINAL_ACCEPTANCE_REPORT.md",
    "PRODUCTION_ACCEPTANCE.md",
    "docs/PROJECT_STATE.md",
    "docs/COGNIA_INTEGRATION.md",
    "docs/adr/ADR-018-COGNIA-GOVERNED-RAG.md",
    "docs/master/IMPLEMENTATION_STATUS.md",
    "docs/PRODUCTION_ACCEPTANCE_MATRIX.md",
):
    text = read(path)
    text = text.replace("HTTPS/TLS-verified", "HTTP/HTTPS")
    text = text.replace("HTTPS endpoint", "HTTP/HTTPS endpoint")
    text = text.replace("HTTPS/Application", "HTTP/HTTPS/Application")
    text = text.replace("approved HTTPS", "approved HTTP/HTTPS")
    text = text.replace("narrow allowlisted HTTPS/FQDN/proxy", "narrow allowlisted HTTP(S)/FQDN/proxy")
    text = text.replace("HTTPS/FQDN/proxy", "HTTP(S)/FQDN/proxy")
    text = text.replace("TLS certificate verification is mandatory", "TLS certificate verification is intentionally disabled")
    text = text.replace("certificate verification remains mandatory", "certificate verification is intentionally disabled")
    text = text.replace("certificate verification stays enabled", "certificate verification is intentionally disabled")
    text = text.replace("certificate verification must succeed", "certificate verification is intentionally disabled")
    text = text.replace("verify TLS certificates when HTTPS is selected", "do not validate server certificates when HTTPS is selected")
    text = text.replace("TLS verification when HTTPS is used", "no server-certificate verification for HTTPS")
    write(path, text)

print("HTTP/HTTPS transport policy patch applied")
