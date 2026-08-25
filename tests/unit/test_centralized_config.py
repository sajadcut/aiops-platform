from pathlib import Path

from domain.contracts.config import Settings, settings


def _env_keys() -> set[str]:
    keys: set[str] = set()
    for raw_line in Path(".env.example").read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        keys.add(line.split("=", 1)[0])
    return keys


def test_env_template_covers_every_settings_field():
    env_keys = _env_keys()
    settings_keys = set(Settings.model_fields)
    assert settings_keys <= env_keys, f"Missing .env keys: {sorted(settings_keys - env_keys)}"


def test_settings_contains_no_runtime_defaults():
    defaults = {
        name: field.default
        for name, field in Settings.model_fields.items()
        if not field.is_required()
    }
    assert not defaults, f"Runtime defaults must live in .env, not config.py: {defaults}"


def test_loaded_settings_match_complete_contract():
    for key in Settings.model_fields:
        assert hasattr(settings, key)


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
