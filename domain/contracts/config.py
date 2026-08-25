from typing import List, Optional

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Typed loader for the centralized runtime environment contract.

    Runtime values MUST come from process environment variables or the root
    ``.env`` file. This module intentionally contains no operational defaults;
    ``.env.example`` documents the complete non-secret template contract.
    """

    APP_NAME: str = Field(...)
    APP_VERSION: str = Field(...)
    APP_ENV: str = Field(...)
    DEBUG: bool = Field(...)
    HOST: str = Field(...)
    PORT: int = Field(...)

    DATABASE_URL: str = Field(...)
    ALEMBIC_DATABASE_URL: Optional[str] = Field(...)
    DATABASE_POOL_SIZE: int = Field(...)
    DATABASE_MAX_OVERFLOW: int = Field(...)

    LLM_PROVIDER: str = Field(...)
    LLM_API_KEY: Optional[str] = Field(...)
    LLM_BASE_URL: Optional[str] = Field(...)
    LLM_MODEL: str = Field(...)
    LLM_TIMEOUT_SECONDS: int = Field(...)

    EMBEDDING_PROVIDER: str = Field(...)
    EMBEDDING_BASE_URL: Optional[str] = Field(...)
    EMBEDDING_API_KEY: Optional[str] = Field(...)
    EMBEDDING_MODEL: str = Field(...)
    EMBEDDING_DIMENSION: int = Field(...)
    EMBEDDING_TIMEOUT_SECONDS: int = Field(...)
    PGVECTOR_EXPECTED_DIMENSION: Optional[int] = Field(...)
    PGVECTOR_VALIDATE_ON_STARTUP: bool = Field(...)

    KNOWLEDGE_ALLOWED_SOURCE_TYPES: List[str] = Field(...)
    KNOWLEDGE_REQUIRE_GOVERNANCE_PRODUCTION: bool = Field(...)

    AGENT_LLM_TEMPERATURE: float = Field(...)
    AGENT_MAX_TOKENS: int = Field(...)
    AGENT_MAX_EVIDENCE_ITEMS: int = Field(...)
    AGENT_MIN_EVIDENCE_ITEMS: int = Field(...)
    AGENT_MIN_EVIDENCE_COVERAGE: float = Field(...)
    AGENT_LOW_CONFIDENCE_THRESHOLD: float = Field(...)
    AGENT_MAX_RECOMMENDATIONS: int = Field(...)
    AGENT_MAX_HYPOTHESES: int = Field(...)
    AGENT_MAX_AUXILIARY_CONTEXT_ITEMS: int = Field(...)
    AGENT_ENABLED_AGENTS: List[str] = Field(...)
    AGENT_MAX_PARALLELISM: int = Field(...)
    AGENT_MAX_EVIDENCE_ROUNDS: int = Field(...)
    AGENT_TIMEOUT_SECONDS: int = Field(...)
    AGENT_STRUCTURED_REPAIR_ATTEMPTS: int = Field(...)
    AGENT_STALE_EVIDENCE_SECONDS: int = Field(...)
    A2A_TIMEOUT_SECONDS: int = Field(...)

    LOG_LEVEL: str = Field(...)
    LOG_JSON: bool = Field(...)
    INTERNAL_API_KEY: Optional[str] = Field(...)
    INTERNAL_API_ROLE: str = Field(...)
    API_RATE_LIMIT_PER_MINUTE: int = Field(...)
    RATE_LIMIT_STRICT_REQUESTS: int = Field(...)
    RATE_LIMIT_LOOSE_REQUESTS: int = Field(...)
    RATE_LIMIT_WINDOW_SECONDS: int = Field(...)
    RETRY_MAX_ATTEMPTS: int = Field(...)
    RETRY_DELAY_SECONDS: float = Field(...)
    RETRY_BACKOFF_FACTOR: float = Field(...)
    CORS_ORIGINS: List[str] = Field(...)
    APPROVAL_TTL_SECONDS: int = Field(...)

    ZABBIX_URL: str = Field(...)
    ZABBIX_USERNAME: Optional[str] = Field(...)
    ZABBIX_PASSWORD: Optional[str] = Field(...)
    ZABBIX_TIMEOUT_SECONDS: int = Field(...)

    ELASTICSEARCH_HOSTS: List[str] = Field(...)
    ELASTICSEARCH_USERNAME: Optional[str] = Field(...)
    ELASTICSEARCH_PASSWORD: Optional[str] = Field(...)
    ELASTICSEARCH_TIMEOUT_SECONDS: int = Field(...)

    PROMETHEUS_URL: str = Field(...)
    PROMETHEUS_TIMEOUT_SECONDS: int = Field(...)

    # Read-only Kubernetes evidence connector. No write verbs are implemented.
    KUBERNETES_API_URL: Optional[str] = Field(...)
    KUBERNETES_TOKEN: Optional[str] = Field(...)
    KUBERNETES_TOKEN_FILE: Optional[str] = Field(...)
    KUBERNETES_CA_CERT_PATH: Optional[str] = Field(...)
    KUBERNETES_NAMESPACE: str = Field(...)
    KUBERNETES_TIMEOUT_SECONDS: int = Field(...)
    KUBERNETES_LOG_TAIL_LINES: int = Field(...)

    SSH_ENABLED: bool = Field(...)
    SSH_USERNAME: str = Field(...)
    SSH_PRIVATE_KEY_PATH: Optional[str] = Field(...)
    SSH_KNOWN_HOSTS: Optional[str] = Field(...)
    SSH_STRICT_HOST_KEY_CHECKING: bool = Field(...)
    SSH_PORT: int = Field(...)
    SSH_CONNECT_TIMEOUT: int = Field(...)
    VM_CPU_RECOVERY_THRESHOLD: float = Field(...)

    OIDC_ISSUER_URL: Optional[str] = Field(...)
    OIDC_AUDIENCE: Optional[str] = Field(...)
    OIDC_JWKS_URL: Optional[str] = Field(...)

    OFFLINE_IMAGE_REGISTRY: Optional[str] = Field(...)
    IMAGE_PULL_POLICY: str = Field(...)

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore",
    )


settings = Settings()
