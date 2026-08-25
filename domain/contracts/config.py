from typing import List, Optional

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Typed loader for the centralized runtime environment contract.

    Runtime values MUST come from process environment variables or the root
    ``.env`` file. This module intentionally contains no operational defaults;
    ``.env.example`` documents the complete non-secret template contract.
    """

    # Application
    APP_NAME: str = Field(...)
    APP_VERSION: str = Field(...)
    APP_ENV: str = Field(...)
    DEBUG: bool = Field(...)
    HOST: str = Field(...)
    PORT: int = Field(...)

    # PostgreSQL / migrations
    DATABASE_URL: str = Field(...)
    ALEMBIC_DATABASE_URL: Optional[str] = Field(...)
    DATABASE_POOL_SIZE: int = Field(...)
    DATABASE_MAX_OVERFLOW: int = Field(...)

    # LLM
    LLM_PROVIDER: str = Field(...)
    LLM_API_KEY: Optional[str] = Field(...)
    LLM_BASE_URL: Optional[str] = Field(...)
    LLM_MODEL: str = Field(...)
    LLM_TIMEOUT_SECONDS: int = Field(...)

    # Embeddings / pgvector
    EMBEDDING_PROVIDER: str = Field(...)
    EMBEDDING_BASE_URL: Optional[str] = Field(...)
    EMBEDDING_API_KEY: Optional[str] = Field(...)
    EMBEDDING_MODEL: str = Field(...)
    EMBEDDING_DIMENSION: int = Field(...)
    EMBEDDING_TIMEOUT_SECONDS: int = Field(...)
    PGVECTOR_EXPECTED_DIMENSION: Optional[int] = Field(...)
    PGVECTOR_VALIDATE_ON_STARTUP: bool = Field(...)

    # Knowledge governance
    KNOWLEDGE_ALLOWED_SOURCE_TYPES: List[str] = Field(...)
    KNOWLEDGE_REQUIRE_GOVERNANCE_PRODUCTION: bool = Field(...)

    # Logging / API / security
    LOG_LEVEL: str = Field(...)
    LOG_JSON: bool = Field(...)
    INTERNAL_API_KEY: Optional[str] = Field(...)
    INTERNAL_API_ROLE: str = Field(...)
    API_RATE_LIMIT_PER_MINUTE: int = Field(...)
    RATE_LIMIT_STRICT_REQUESTS: int = Field(...)
    RATE_LIMIT_LOOSE_REQUESTS: int = Field(...)
    RATE_LIMIT_WINDOW_SECONDS: int = Field(...)
    CORS_ORIGINS: List[str] = Field(...)
    APPROVAL_TTL_SECONDS: int = Field(...)

    # Zabbix
    ZABBIX_URL: str = Field(...)
    ZABBIX_USERNAME: Optional[str] = Field(...)
    ZABBIX_PASSWORD: Optional[str] = Field(...)
    ZABBIX_TIMEOUT_SECONDS: int = Field(...)

    # Elasticsearch
    ELASTICSEARCH_HOSTS: List[str] = Field(...)
    ELASTICSEARCH_USERNAME: Optional[str] = Field(...)
    ELASTICSEARCH_PASSWORD: Optional[str] = Field(...)
    ELASTICSEARCH_TIMEOUT_SECONDS: int = Field(...)

    # Prometheus
    PROMETHEUS_URL: str = Field(...)
    PROMETHEUS_TIMEOUT_SECONDS: int = Field(...)

    # VM / SSH
    SSH_ENABLED: bool = Field(...)
    SSH_USERNAME: str = Field(...)
    SSH_PRIVATE_KEY_PATH: Optional[str] = Field(...)
    SSH_KNOWN_HOSTS: Optional[str] = Field(...)
    SSH_STRICT_HOST_KEY_CHECKING: bool = Field(...)
    SSH_PORT: int = Field(...)
    SSH_CONNECT_TIMEOUT: int = Field(...)
    VM_CPU_RECOVERY_THRESHOLD: float = Field(...)

    # OIDC / SSO
    OIDC_ISSUER_URL: Optional[str] = Field(...)
    OIDC_AUDIENCE: Optional[str] = Field(...)
    OIDC_JWKS_URL: Optional[str] = Field(...)

    # Offline deployment
    OFFLINE_IMAGE_REGISTRY: Optional[str] = Field(...)
    IMAGE_PULL_POLICY: str = Field(...)

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore",
    )


settings = Settings()
