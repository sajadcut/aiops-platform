from pathlib import Path

from domain.contracts.config import settings


CANONICAL_KEYS = {
    "DATABASE_URL",
    "LLM_API_KEY",
    "LLM_BASE_URL",
    "ZABBIX_URL",
    "ZABBIX_USERNAME",
    "ZABBIX_PASSWORD",
    "ELASTICSEARCH_HOSTS",
    "ELASTICSEARCH_USERNAME",
    "ELASTICSEARCH_PASSWORD",
    "PROMETHEUS_URL",
    "OIDC_ISSUER_URL",
    "OIDC_AUDIENCE",
    "OIDC_JWKS_URL",
    "INTERNAL_API_KEY",
    "OFFLINE_IMAGE_REGISTRY",
}


def test_canonical_env_contract_contains_all_external_configuration_keys():
    text = Path(".env.example").read_text(encoding="utf-8")
    missing = [key for key in CANONICAL_KEYS if f"{key}=" not in text]
    assert not missing, f"Missing centralized config keys: {missing}"


def test_settings_exposes_external_configuration():
    for key in CANONICAL_KEYS:
        assert hasattr(settings, key)
