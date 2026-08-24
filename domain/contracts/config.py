from typing import List, Optional

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Single source of truth for runtime configuration.

    Application code and integration adapters must read configuration from this
    object instead of embedding URLs, usernames, passwords or API keys.
    `.env.example` documents the complete configuration contract.
    """

    # Application
    APP_NAME: str = "AI Ops NeoBankingOperation Platform"
    APP_VERSION: str = "0.1.0"
    APP_ENV: str = "development"
    DEBUG: bool = False
    HOST: str = "0.0.0.0"
    PORT: int = 8000

    # PostgreSQL
    DATABASE_URL: Optional[str] = Field(default="postgresql+asyncpg://user:password@localhost:5432/aiops")
    DATABASE_POOL_SIZE: int = 10
    DATABASE_MAX_OVERFLOW: int = 20

    # LLM / AI Gateway
    LLM_PROVIDER: str = "mock"
    LLM_API_KEY: Optional[str] = None
    LLM_BASE_URL: Optional[str] = None
    LLM_MODEL: str = "gpt-4"
    LLM_TIMEOUT_SECONDS: int = 60

    # Logging / API
    LOG_LEVEL: str = "INFO"
    LOG_JSON: bool = False
    INTERNAL_API_KEY: Optional[str] = None
    API_RATE_LIMIT_PER_MINUTE: int = 120
    CORS_ORIGINS: List[str] = ["*"]

    # Zabbix
    ZABBIX_URL: str = "http://localhost:8080"
    ZABBIX_USERNAME: Optional[str] = None
    ZABBIX_PASSWORD: Optional[str] = None
    ZABBIX_TIMEOUT_SECONDS: int = 10

    # Elasticsearch
    ELASTICSEARCH_HOSTS: List[str] = ["http://localhost:9200"]
    ELASTICSEARCH_USERNAME: Optional[str] = None
    ELASTICSEARCH_PASSWORD: Optional[str] = None
    ELASTICSEARCH_TIMEOUT_SECONDS: int = 10

    # Prometheus
    PROMETHEUS_URL: str = "http://localhost:9090"
    PROMETHEUS_TIMEOUT_SECONDS: int = 10

    # OIDC / SSO
    OIDC_ISSUER_URL: Optional[str] = None
    OIDC_AUDIENCE: Optional[str] = None
    OIDC_JWKS_URL: Optional[str] = None

    # PostgreSQL / pgvector
    PGVECTOR_EXPECTED_DIMENSION: Optional[int] = None
    PGVECTOR_VALIDATE_ON_STARTUP: bool = True

    # Offline deployment / registry
    OFFLINE_IMAGE_REGISTRY: Optional[str] = None
    IMAGE_PULL_POLICY: str = "IfNotPresent"

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore",
    )


settings = Settings()
