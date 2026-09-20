from pathlib import Path

import pytest
from pydantic import ValidationError

from domain.contracts.config import Settings, settings


def _template_keys() -> set[str]:
    keys: set[str] = set()
    for raw_line in Path(".env.example").read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        keys.add(line.split("=", 1)[0])
    return keys


def _template_values() -> dict[str, str]:
    values: dict[str, str] = {}
    for raw_line in Path(".env.example").read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key] = value.strip()
    return values


def _settings_data(**overrides):
    data = settings.model_dump()
    data.update(overrides)
    return data


def test_canonical_env_template_covers_every_settings_field():
    env_keys = _template_keys()
    settings_keys = set(Settings.model_fields)
    assert settings_keys <= env_keys, f"Missing .env.example keys: {sorted(settings_keys - env_keys)}"


def test_populated_env_is_ignored_and_template_is_tracked_contract():
    gitignore = Path(".gitignore").read_text(encoding="utf-8").splitlines()
    assert ".env" in gitignore
    assert "!.env.example" in gitignore
    assert Path(".env.example").exists()


def test_settings_contains_no_runtime_defaults():
    defaults = {
        name: field.default
        for name, field in Settings.model_fields.items()
        if not field.is_required()
    }
    assert not defaults, f"Runtime defaults must live in .env.example, not config.py: {defaults}"


def test_loaded_settings_match_complete_contract():
    for key in Settings.model_fields:
        assert hasattr(settings, key)


def test_cognia_is_the_only_rag_and_template_has_no_provider_switch():
    values = _template_values()
    assert ("KNOWLEDGE_" + "PROVIDER") not in values
    assert ("KNOWLEDGE_ALLOWED_" + "SOURCE_TYPES") not in values
    assert ("KNOWLEDGE_REQUIRE_GOVERNANCE_" + "PRODUCTION") not in values
    assert values["COGNIA_CLIENT_SECRET"] == ""
    assert values["COGNIA_CLIENT_ID"] == ""
    assert values["COGNIA_BASE_URL"] == ""
    assert values["COGNIA_CLIENT_APPLICATION_ID"] == ""


def test_production_cognia_requires_machine_identity_and_explicit_kbs():
    with pytest.raises(ValidationError, match="Cognia RAG requires"):
        Settings(
            _env_file=None,
            **_settings_data(
                APP_ENV="production",
                COGNIA_BASE_URL="https://cognia.test",
                COGNIA_CLIENT_ID="",
                COGNIA_CLIENT_SECRET="",
                COGNIA_KNOWLEDGE_BASE_IDS=[],
            ),
        )


def test_production_cognia_supports_http_and_https_transport_contract():
    base = _settings_data(
        APP_ENV="production",
        COGNIA_CLIENT_ID="app-id",
        COGNIA_CLIENT_SECRET="test-only-secret",
        COGNIA_KNOWLEDGE_BASE_IDS=[10],
    )

    assert Settings(_env_file=None, **{**base, "COGNIA_BASE_URL": "http://cognia.test"}).COGNIA_BASE_URL == "http://cognia.test"
    assert Settings(_env_file=None, **{**base, "COGNIA_BASE_URL": "https://cognia.test"}).COGNIA_BASE_URL == "https://cognia.test"

    with pytest.raises(ValidationError, match="COGNIA_BASE_URL must use HTTP or HTTPS"):
        Settings(_env_file=None, **{**base, "COGNIA_BASE_URL": "ftp://cognia.test"})


def test_production_cognia_accepts_machine_identity_and_explicit_kbs():
    configured = Settings(
        _env_file=None,
        **_settings_data(
            APP_ENV="production",
            COGNIA_BASE_URL="https://cognia.test",
            COGNIA_CLIENT_ID="app-id",
            COGNIA_CLIENT_SECRET="test-only-secret",
            COGNIA_KNOWLEDGE_BASE_IDS=[10, 20],
        ),
    )
    assert configured.COGNIA_KNOWLEDGE_BASE_IDS == [10, 20]


def test_optional_cognia_numeric_ids_parse_empty_template_values_as_none():
    values = _settings_data(COGNIA_CLIENT_APPLICATION_ID="", COGNIA_CONTEXT_PROFILE_ID="")
    configured = Settings(_env_file=None, **values)
    assert configured.COGNIA_CLIENT_APPLICATION_ID is None
    assert configured.COGNIA_CONTEXT_PROFILE_ID is None


def test_jenkins_mcp_template_is_off_by_default_and_keeps_credentials_empty():
    values = _template_values()
    assert values["JENKINS_MCP_URL"] == ""
    assert values["JENKINS_MCP_PROTOCOL_VERSION"] == "2025-06-18"
    assert values["JENKINS_MCP_AUTH_HEADER"] == ""
    assert values["JENKINS_MCP_WRITE_AUTH_HEADER"] == ""
    assert values["JENKINS_MCP_EXPECTED_IDENTITY"] == ""
    assert values["JENKINS_MCP_ENABLE_WRITES"] == "False"


def test_jenkins_mcp_requires_official_streamable_endpoint_and_basic_auth():
    base = _settings_data()

    with pytest.raises(ValidationError, match="/mcp-server/mcp"):
        Settings(_env_file=None, **{**base, "JENKINS_MCP_URL": "https://jenkins.test/mcp"})

    with pytest.raises(ValidationError, match="Authorization: Basic"):
        Settings(
            _env_file=None,
            **{
                **base,
                "JENKINS_MCP_URL": "https://jenkins.test/mcp-server/mcp",
                "JENKINS_MCP_AUTH_HEADER": "Bearer not-supported",
            },
        )


def test_production_jenkins_mcp_requires_authenticated_expected_identity():
    base = _settings_data(
        APP_ENV="production",
        COGNIA_BASE_URL="https://cognia.test",
        COGNIA_CLIENT_ID="app-id",
        COGNIA_CLIENT_SECRET="test-only-secret",
        COGNIA_KNOWLEDGE_BASE_IDS=[10],
        JENKINS_MCP_URL="https://jenkins.test/mcp-server/mcp",
    )

    with pytest.raises(ValidationError, match="JENKINS_MCP_AUTH_HEADER"):
        Settings(_env_file=None, **base)

    with pytest.raises(ValidationError, match="JENKINS_MCP_EXPECTED_IDENTITY"):
        Settings(
            _env_file=None,
            **{**base, "JENKINS_MCP_AUTH_HEADER": "Basic dXNlcjp0b2tlbg=="},
        )

    configured = Settings(
        _env_file=None,
        **{
            **base,
            "JENKINS_MCP_AUTH_HEADER": "Basic dXNlcjp0b2tlbg==",
            "JENKINS_MCP_EXPECTED_IDENTITY": "aiops-reader",
        },
    )
    assert configured.JENKINS_MCP_URL.endswith("/mcp-server/mcp")


def test_jenkins_mcp_writes_require_separate_basic_identity():
    base = _settings_data(
        JENKINS_MCP_URL="https://jenkins.test/mcp-server/mcp",
        JENKINS_MCP_AUTH_HEADER="Basic dXNlcjp0b2tlbg==",
        JENKINS_MCP_ENABLE_WRITES=True,
    )
    with pytest.raises(ValidationError, match="JENKINS_MCP_WRITE_AUTH_HEADER"):
        Settings(_env_file=None, **base)

    configured = Settings(
        _env_file=None,
        **{**base, "JENKINS_MCP_WRITE_AUTH_HEADER": "Basic d3JpdGU6dG9rZW4="},
    )
    assert configured.JENKINS_MCP_ENABLE_WRITES is True


def test_alembic_does_not_bypass_centralized_settings():
    source = Path("database/migrations/env.py").read_text(encoding="utf-8")
    assert "os.getenv" not in source
    assert "settings.ALEMBIC_DATABASE_URL" in source


def test_rate_limits_are_not_hardcoded_in_runtime_module():
    source = Path("domain/contracts/rate_limit.py").read_text(encoding="utf-8")
    assert "settings.API_RATE_LIMIT_PER_MINUTE" in source
    assert "settings.RATE_LIMIT_STRICT_REQUESTS" in source
    assert "settings.RATE_LIMIT_LOOSE_REQUESTS" in source
    assert "settings.RATE_LIMIT_WINDOW_SECONDS" in source


def test_elastic_agent_builder_provider_contract_is_pinned_and_isolated():
    values = _template_values()
    assert values["ELASTICSEARCH_MCP_PROTOCOL_VERSION"] == "2024-11-05"
    assert values["ELASTICSEARCH_MCP_AUTH_HEADER"] == ""

    configured = Settings(
        _env_file=None,
        **_settings_data(
            ELASTICSEARCH_MCP_URL="https://kibana.test/s/ops/api/agent_builder/mcp",
            ELASTICSEARCH_MCP_PROTOCOL_VERSION="2024-11-05",
            ELASTICSEARCH_MCP_AUTH_HEADER="ApiKey test-key",
        ),
    )
    assert configured.ELASTICSEARCH_MCP_AUTH_HEADER == "ApiKey test-key"

    with pytest.raises(ValidationError, match="2024-11-05"):
        Settings(
            _env_file=None,
            **_settings_data(ELASTICSEARCH_MCP_PROTOCOL_VERSION="2025-03-26"),
        )

    with pytest.raises(ValidationError, match="ApiKey or Bearer"):
        Settings(
            _env_file=None,
            **_settings_data(ELASTICSEARCH_MCP_AUTH_HEADER="Basic dXNlcjpwYXNz"),
        )

    with pytest.raises(ValidationError, match="must target"):
        Settings(
            _env_file=None,
            **_settings_data(ELASTICSEARCH_MCP_URL="https://kibana.test/not/api/agent_builder/mcp/extra"),
        )
