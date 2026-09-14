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


def test_cognia_secret_is_empty_in_tracked_template():
    values = _template_values()
    assert values["COGNIA_CLIENT_SECRET"] == ""
    assert values["COGNIA_CLIENT_ID"] == ""
    assert values["COGNIA_BASE_URL"] == ""


def test_governed_production_rejects_local_knowledge_provider():
    with pytest.raises(ValidationError, match="production governed knowledge requires KNOWLEDGE_PROVIDER=cognia"):
        Settings(
            _env_file=None,
            **_settings_data(
                APP_ENV="production",
                KNOWLEDGE_PROVIDER="local_pgvector",
                KNOWLEDGE_REQUIRE_GOVERNANCE_PRODUCTION=True,
            ),
        )


def test_production_cognia_requires_https_and_tls_verification():
    base = _settings_data(
        APP_ENV="production",
        KNOWLEDGE_PROVIDER="cognia",
        KNOWLEDGE_REQUIRE_GOVERNANCE_PRODUCTION=True,
        COGNIA_CLIENT_ID="app-id",
        COGNIA_CLIENT_SECRET="test-only-secret",
        COGNIA_KNOWLEDGE_BASE_IDS=[10],
    )
    with pytest.raises(ValidationError, match="COGNIA_BASE_URL must use HTTPS"):
        Settings(_env_file=None, **{**base, "COGNIA_BASE_URL": "http://cognia.test", "COGNIA_TLS_VERIFY": True})

    with pytest.raises(ValidationError, match="COGNIA_TLS_VERIFY must be enabled"):
        Settings(_env_file=None, **{**base, "COGNIA_BASE_URL": "https://cognia.test", "COGNIA_TLS_VERIFY": False})


def test_production_cognia_accepts_machine_identity_and_explicit_kbs():
    configured = Settings(
        _env_file=None,
        **_settings_data(
            APP_ENV="production",
            KNOWLEDGE_PROVIDER="cognia",
            KNOWLEDGE_REQUIRE_GOVERNANCE_PRODUCTION=True,
            COGNIA_BASE_URL="https://cognia.test",
            COGNIA_CLIENT_ID="app-id",
            COGNIA_CLIENT_SECRET="test-only-secret",
            COGNIA_KNOWLEDGE_BASE_IDS=[10, 20],
            COGNIA_TLS_VERIFY=True,
        ),
    )
    assert configured.COGNIA_KNOWLEDGE_BASE_IDS == [10, 20]


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
