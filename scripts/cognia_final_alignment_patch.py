from pathlib import Path


def replace(path: str, old: str, new: str) -> None:
    p = Path(path)
    text = p.read_text(encoding="utf-8")
    if old not in text:
        raise SystemExit(f"marker not found in {path}: {old[:160]!r}")
    if text.count(old) != 1:
        raise SystemExit(f"marker not unique in {path}: count={text.count(old)}")
    p.write_text(text.replace(old, new, 1), encoding="utf-8")


# Cognia supports both HTTP and HTTPS because the supplied Cognia environment
# contract exposes HTTP as a valid endpoint. If HTTPS is selected in Production,
# certificate verification remains fail-closed.
replace(
    "domain/contracts/config.py",
    '''            if urlparse(str(self.COGNIA_BASE_URL or "")).scheme != "https":\n                raise ValueError("COGNIA_BASE_URL must use HTTPS in production")\n            if not self.COGNIA_TLS_VERIFY:\n                raise ValueError("COGNIA_TLS_VERIFY must be enabled in production")\n''',
    '''            cognia_scheme = urlparse(str(self.COGNIA_BASE_URL or "")).scheme.lower()\n            if cognia_scheme not in {"http", "https"}:\n                raise ValueError("COGNIA_BASE_URL must use HTTP or HTTPS")\n            if cognia_scheme == "https" and not self.COGNIA_TLS_VERIFY:\n                raise ValueError("COGNIA_TLS_VERIFY must be enabled when Cognia uses HTTPS in production")\n''',
)

replace(
    "tests/unit/test_centralized_config.py",
    '''def test_production_cognia_requires_https_and_tls_verification():\n    base = _settings_data(\n        APP_ENV="production",\n        COGNIA_CLIENT_ID="app-id",\n        COGNIA_CLIENT_SECRET="test-only-secret",\n        COGNIA_KNOWLEDGE_BASE_IDS=[10],\n    )\n    with pytest.raises(ValidationError, match="COGNIA_BASE_URL must use HTTPS"):\n        Settings(_env_file=None, **{**base, "COGNIA_BASE_URL": "http://cognia.test", "COGNIA_TLS_VERIFY": True})\n\n    with pytest.raises(ValidationError, match="COGNIA_TLS_VERIFY must be enabled"):\n        Settings(_env_file=None, **{**base, "COGNIA_BASE_URL": "https://cognia.test", "COGNIA_TLS_VERIFY": False})\n''',
    '''def test_production_cognia_supports_http_and_https_transport_contract():\n    base = _settings_data(\n        APP_ENV="production",\n        COGNIA_CLIENT_ID="app-id",\n        COGNIA_CLIENT_SECRET="test-only-secret",\n        COGNIA_KNOWLEDGE_BASE_IDS=[10],\n    )\n\n    http_config = Settings(\n        _env_file=None,\n        **{**base, "COGNIA_BASE_URL": "http://cognia.test", "COGNIA_TLS_VERIFY": False},\n    )\n    assert http_config.COGNIA_BASE_URL == "http://cognia.test"\n\n    https_config = Settings(\n        _env_file=None,\n        **{**base, "COGNIA_BASE_URL": "https://cognia.test", "COGNIA_TLS_VERIFY": True},\n    )\n    assert https_config.COGNIA_BASE_URL == "https://cognia.test"\n\n    with pytest.raises(ValidationError, match="COGNIA_TLS_VERIFY must be enabled when Cognia uses HTTPS"):\n        Settings(_env_file=None, **{**base, "COGNIA_BASE_URL": "https://cognia.test", "COGNIA_TLS_VERIFY": False})\n\n    with pytest.raises(ValidationError, match="COGNIA_BASE_URL must use HTTP or HTTPS"):\n        Settings(_env_file=None, **{**base, "COGNIA_BASE_URL": "ftp://cognia.test", "COGNIA_TLS_VERIFY": True})\n''',
)

replace(
    ".env.example",
    '''# retrieval then reports a typed Cognia misconfiguration instead of falling back.\nCOGNIA_BASE_URL=\n''',
    '''# retrieval then reports a typed Cognia misconfiguration instead of falling back.\n# COGNIA_BASE_URL supports http:// and https://. When https:// is used in\n# production, COGNIA_TLS_VERIFY must remain enabled.\nCOGNIA_BASE_URL=\n''',
)

# Canonical Cognia integration documentation.
replace(
    "docs/COGNIA_INTEGRATION.md",
    '''Production requires an approved HTTPS Cognia endpoint with TLS verification. Secrets come from the deployment secret store and are covered by recursive redaction. If Cognia is outside the Kubernetes namespace/cluster, infrastructure must provide a narrow allowlisted HTTPS/FQDN/proxy egress path; unrestricted Internet egress is not added to the application NetworkPolicy.''',
    '''Cognia transport supports both HTTP and HTTPS because the supplied Cognia environment contract exposes HTTP. If HTTPS is configured in Production, certificate verification remains mandatory. Secrets come from the deployment secret store and are covered by recursive redaction. If Cognia is outside the Kubernetes namespace/cluster, infrastructure must provide a narrow allowlisted route to the configured Cognia host/port (or an approved proxy); unrestricted Internet egress is not added to the application NetworkPolicy.''',
)

replace(
    "docs/adr/ADR-018-COGNIA-GOVERNED-RAG.md",
    '''- Production Cognia endpoint must be HTTPS and certificate verification stays enabled.''',
    '''- Cognia endpoints may use HTTP or HTTPS according to the deployed Cognia environment contract. When HTTPS is used in Production, certificate verification stays enabled.''',
)
replace(
    "docs/adr/ADR-018-COGNIA-GOVERNED-RAG.md",
    '''Production PASS still requires real non-production Cognia evidence: approved HTTPS endpoint, Application Client credential rotation, exact KB grants, positive/negative Search authorization, General/ClientApplication/ExternalSubject scope tests where used, registration → processing → Activated → Search, index/dependency outage behavior, and Context Profile/sufficiency tests if Context Generation is enabled.''',
    '''Production PASS still requires real non-production Cognia evidence: the approved target HTTP/HTTPS endpoint, Application Client credential rotation, exact KB grants, positive/negative Search authorization, General/ClientApplication/ExternalSubject scope tests where used, registration → processing → Activated → Search, index/dependency outage behavior, and Context Profile/sufficiency tests if Context Generation is enabled.''',
)

# Central configuration docs must match runtime validation.
replace(
    "docs/CONFIGURATION.md",
    '''- Cognia RAG lacks Application Client credentials, an explicit positive KB allowlist, HTTPS or TLS verification;''',
    '''- Cognia RAG lacks Application Client credentials or an explicit positive KB allowlist, uses a non-HTTP(S) URL, or uses HTTPS with TLS verification disabled;''',
)
replace(
    "docs/CONFIGURATION.md",
    '''- The supplied sandpod guide uses HTTP; production AIOps still requires an approved HTTPS endpoint with TLS verification.''',
    '''- The supplied sandpod guide uses HTTP and AIOps supports it. HTTPS is also supported; when HTTPS is selected in Production, TLS certificate verification is mandatory.''',
)
replace(
    "docs/CONFIGURATION.md",
    '''| `COGNIA_BASE_URL` | Cognia client/readiness | No | Required in production because Cognia is the only Knowledge RAG; production requires HTTPS. Do not hard-code the sandpod URL into production. |''',
    '''| `COGNIA_BASE_URL` | Cognia client/readiness | No | Required in production because Cognia is the only Knowledge RAG; both `http://` and `https://` are supported. Use the environment-specific Cognia endpoint. |''',
)
replace(
    "docs/CONFIGURATION.md",
    '''| `COGNIA_TIMEOUT_SECONDS`, `COGNIA_TLS_VERIFY` | Cognia transport | No | Timeout must be positive; production requires TLS verification. |''',
    '''| `COGNIA_TIMEOUT_SECONDS`, `COGNIA_TLS_VERIFY` | Cognia transport | No | Timeout must be positive. `COGNIA_TLS_VERIFY` is enforced when Production Cognia uses HTTPS; it has no TLS effect for HTTP transport. |''',
)
replace(
    "docs/CONFIGURATION.md",
    '''- **Cognia environment boundary:** the supplied consumer documentation describes a sandpod endpoint over HTTP. Production AIOps must receive an environment-specific HTTPS Cognia endpoint and must not disable certificate verification to accommodate a test endpoint.''',
    '''- **Cognia environment boundary:** the supplied consumer documentation describes a sandpod endpoint over HTTP, and AIOps intentionally supports both HTTP and HTTPS Cognia endpoints. For HTTPS in Production, certificate verification must remain enabled.''',
)

# Acceptance/status docs: transport scheme is not itself a blocker; real endpoint
# connectivity/auth/grants/lifecycle still are.
replace(
    "docs/PROJECT_STATE.md",
    '''Required evidence includes HTTPS/TLS, Client Application credential issuance/rotation, exact KB grants, positive and negative authorization, Scope isolation, registration → Approval when applicable → Processing → `Activated` → Search, Search dependency/index outage with explicit degradation, and Context Profile/sufficiency behavior if Context Generation is enabled.''',
    '''Required evidence includes the approved target HTTP/HTTPS endpoint (and TLS verification when HTTPS is used), Client Application credential issuance/rotation, exact KB grants, positive and negative authorization, Scope isolation, registration → Approval when applicable → Processing → `Activated` → Search, Search dependency/index outage with explicit degradation, and Context Profile/sufficiency behavior if Context Generation is enabled.''',
)
replace(
    "docs/PROJECT_STATE.md",
    '''The supplied sandpod documentation currently names an HTTP endpoint. That endpoint is suitable only for controlled non-Production acceptance; Production startup requires an approved HTTPS Cognia URL with TLS verification enabled.''',
    '''The supplied sandpod documentation names an HTTP endpoint, and AIOps supports that transport. Production may use the approved Cognia HTTP or HTTPS endpoint for the target environment; when HTTPS is used, TLS verification remains mandatory.''',
)
replace(
    "docs/PROJECT_STATE.md",
    '''1. Acceptance-test Cognia against the real non-Production endpoint with an Application Client, exact KB grants and representative Knowledge/Scope lifecycle; provision an HTTPS Production endpoint/route before promotion.''',
    '''1. Acceptance-test Cognia against the real target HTTP/HTTPS endpoint with an Application Client, exact KB grants and representative Knowledge/Scope lifecycle; verify TLS certificates when HTTPS is selected.''',
)
replace(
    "docs/PROJECT_STATE.md",
    '''- Real Cognia HTTPS/Application Client/KB grant/Scope/Search/lifecycle acceptance and optional Context Profile acceptance.''',
    '''- Real Cognia HTTP/HTTPS endpoint, Application Client/KB grant/Scope/Search/lifecycle acceptance and optional Context Profile acceptance.''',
)

replace(
    "MASTER.md",
    '''- Real Cognia HTTPS endpoint, Application Client identity, KB grants, Scope/Search and optional Context Profile have not yet been externally accepted.''',
    '''- Real Cognia HTTP/HTTPS endpoint, Application Client identity, KB grants, Scope/Search and optional Context Profile have not yet been externally accepted.''',
)
replace(
    "MASTER.md",
    '''1. Real Cognia HTTPS/Application Client/KB grant/Search/Scope acceptance, including outage/no-fallback evidence.''',
    '''1. Real Cognia HTTP/HTTPS endpoint + Application Client/KB grant/Search/Scope acceptance, including outage/no-fallback evidence.''',
)

replace(
    "docs/master/IMPLEMENTATION_STATUS.md",
    '''1. Real Cognia HTTPS endpoint + Application Client authentication, assigned KB grants and Search against the exact configured KB IDs.''',
    '''1. Real Cognia target HTTP/HTTPS endpoint + Application Client authentication, assigned KB grants and Search against the exact configured KB IDs; verify certificates when HTTPS is selected.''',
)

replace(
    "docs/PRODUCTION_ACCEPTANCE_MATRIX.md",
    '''1. Real Cognia Application Client authentication over the target environment's approved HTTPS endpoint.''',
    '''1. Real Cognia Application Client authentication over the target environment's approved HTTP or HTTPS endpoint; when HTTPS is selected, certificate verification must succeed.''',
)

replace(
    "FINAL_ACCEPTANCE_REPORT.md",
    '''| Cognia-only Governed Knowledge RAG | sole RAG provider; Application Client machine auth; opaque token lifecycle; explicit KBs; separate numeric Scope identity; Active-Revision Chunk traceability; typed status/errors; no alternate-RAG fallback; authoring idempotency; Revision concurrency; no machine approval; optional Context Generation | PASS (repo contract); **REAL ENV REQUIRED** for HTTPS endpoint/grants/scope/lifecycle/index/context acceptance |''',
    '''| Cognia-only Governed Knowledge RAG | sole RAG provider; Application Client machine auth; opaque token lifecycle; explicit KBs; separate numeric Scope identity; Active-Revision Chunk traceability; typed status/errors; no alternate-RAG fallback; authoring idempotency; Revision concurrency; no machine approval; optional Context Generation | PASS (repo contract); **REAL ENV REQUIRED** for target HTTP/HTTPS endpoint/grants/scope/lifecycle/index/context acceptance |''',
)
replace(
    "FINAL_ACCEPTANCE_REPORT.md",
    '''| Cognia production network path | default-deny app network retained; narrow approved HTTPS/FQDN/proxy route is an infrastructure responsibility | REAL ENV REQUIRED |''',
    '''| Cognia production network path | default-deny app network retained; narrow approved route to the configured Cognia host/port (HTTP or HTTPS) or approved proxy is an infrastructure responsibility | REAL ENV REQUIRED |''',
)
replace(
    "FINAL_ACCEPTANCE_REPORT.md",
    '''12. Production configuration fails closed unless an HTTPS/TLS-verified Cognia endpoint, machine credentials and explicit KB IDs are supplied.''',
    '''12. Production configuration fails closed unless Cognia uses HTTP or HTTPS with machine credentials and explicit KB IDs; when HTTPS is selected, TLS certificate verification is mandatory.''',
)
replace(
    "FINAL_ACCEPTANCE_REPORT.md",
    '''1. Real Cognia Application Client/HTTPS/KB grants plus positive/negative Search authorization, Scope isolation, registration → Approval where required → Processing → Activated → Search, index/dependency outage/no-fallback and optional Context Profile/sufficiency acceptance.''',
    '''1. Real Cognia Application Client/target HTTP-or-HTTPS endpoint/KB grants plus positive/negative Search authorization, Scope isolation, registration → Approval where required → Processing → Activated → Search, index/dependency outage/no-fallback and optional Context Profile/sufficiency acceptance.''',
)

replace(
    "PRODUCTION_ACCEPTANCE.md",
    '''mandatory Cognia HTTPS/TLS/credentials/KBs''',
    '''mandatory Cognia HTTP-or-HTTPS endpoint/credentials/KBs and TLS verification when HTTPS is used''',
)
