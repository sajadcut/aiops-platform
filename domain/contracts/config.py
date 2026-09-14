from typing import Dict, List, Optional
from urllib.parse import urlparse

from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Typed loader for the centralized runtime environment contract.

    ``.env.example`` is a non-secret development template. A local ``.env`` may
    override it, while real deployment environment variables take precedence
    over both files. Production startup validation is intentionally fail-closed.
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
    DATABASE_VALIDATE_MIGRATIONS_ON_STARTUP: bool = Field(...)

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

    KNOWLEDGE_PROVIDER: str = Field(...)
    KNOWLEDGE_ALLOWED_SOURCE_TYPES: List[str] = Field(...)
    KNOWLEDGE_REQUIRE_GOVERNANCE_PRODUCTION: bool = Field(...)
    COGNIA_BASE_URL: Optional[str] = Field(...)
    COGNIA_CLIENT_ID: Optional[str] = Field(...)
    COGNIA_CLIENT_SECRET: Optional[str] = Field(...)
    COGNIA_KNOWLEDGE_BASE_IDS: List[int] = Field(...)
    COGNIA_CONTEXT_PROFILE_ID: Optional[int] = Field(...)
    COGNIA_TIMEOUT_SECONDS: int = Field(...)
    COGNIA_TLS_VERIFY: bool = Field(...)

    AGENT_LLM_TEMPERATURE: float = Field(...)
    AGENT_MAX_TOKENS: int = Field(...)
    AGENT_MAX_EVIDENCE_ITEMS: int = Field(...)
    AGENT_MIN_EVIDENCE_ITEMS: int = Field(...)
    AGENT_MIN_EVIDENCE_COVERAGE: float = Field(...)
    AGENT_LOW_CONFIDENCE_THRESHOLD: float = Field(...)
    AGENT_MIN_CONSENSUS_SCORE: float = Field(...)
    AGENT_SOURCE_QUALITY_WEIGHTS: Dict[str, float] = Field(...)
    AGENT_MAX_RECOMMENDATIONS: int = Field(...)
    AGENT_MAX_HYPOTHESES: int = Field(...)
    AGENT_MAX_AUXILIARY_CONTEXT_ITEMS: int = Field(...)
    AGENT_ENABLED_AGENTS: List[str] = Field(...)
    AGENT_MAX_PARALLELISM: int = Field(...)
    AGENT_MAX_EVIDENCE_ROUNDS: int = Field(...)
    AGENT_MAX_DYNAMIC_EVIDENCE_TYPES: int = Field(...)
    AGENT_INITIAL_EVIDENCE_WINDOW_SECONDS: int = Field(...)
    AGENT_REFRESH_EVIDENCE_WINDOW_SECONDS: int = Field(...)
    AGENT_TIMEOUT_SECONDS: int = Field(...)
    AGENT_STRUCTURED_REPAIR_ATTEMPTS: int = Field(...)
    AGENT_STALE_EVIDENCE_SECONDS: int = Field(...)
    AGENT_DISAGREEMENT_CONFIDENCE_FACTOR: float = Field(...)
    AGENT_MISSING_EVIDENCE_CONFIDENCE_FACTOR: float = Field(...)
    AGENT_CONFLICT_CONFIDENCE_PENALTY: float = Field(...)
    A2A_TIMEOUT_SECONDS: int = Field(...)
    A2A_ALLOWED_TARGETS: List[str] = Field(...)
    A2A_REQUIRE_HTTPS: bool = Field(...)

    SIGNAL_CORRELATION_ENABLED: bool = Field(...)
    SIGNAL_CORRELATION_WINDOW_SECONDS: int = Field(..., ge=1, le=3600)
    SIGNAL_CORRELATION_CANDIDATE_LIMIT: int = Field(..., ge=1, le=100)

    LOG_LEVEL: str = Field(...)
    LOG_CONSOLE_ENABLED: bool = Field(...)
    LOG_TEXT_FILE_ENABLED: bool = Field(...)
    LOG_JSON_FILE_ENABLED: bool = Field(...)
    LOG_DIR: str = Field(...)
    LOG_TEXT_FILE: str = Field(...)
    LOG_JSON_FILE: str = Field(...)
    LOG_ROTATION_MODE: str = Field(...)
    LOG_MAX_BYTES: int = Field(..., ge=1024)
    LOG_BACKUP_COUNT: int = Field(..., ge=0)
    LOG_ROTATION_WHEN: str = Field(...)
    LOG_ROTATION_INTERVAL: int = Field(..., ge=1)
    LOG_UTC: bool = Field(...)
    LOG_HTTP_BODY_ENABLED: bool = Field(...)
    LOG_HTTP_BODY_MAX_BYTES: int = Field(..., ge=256, le=1048576)

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

    MCP_PROTOCOL_VERSION: str = Field(...)
    MCP_REQUIRE_HTTPS: bool = Field(...)
    MCP_BEARER_TOKEN: Optional[str] = Field(...)
    MCP_WRITE_BEARER_TOKEN: Optional[str] = Field(...)
    MCP_CA_CERT_PATH: Optional[str] = Field(...)
    MCP_CLIENT_CERT_PATH: Optional[str] = Field(...)
    MCP_CLIENT_KEY_PATH: Optional[str] = Field(...)
    MCP_TIMEOUT_SECONDS: int = Field(...)
    MCP_SERVER_PROVIDER: str = Field(...)
    MCP_SERVER_REQUIRE_AUTH: bool = Field(...)

    ZABBIX_MCP_URL: str = Field(...)
    ZABBIX_MCP_SERVER_NAME: Optional[str] = Field(...)
    ZABBIX_MCP_AUTH_HEADER: Optional[str] = Field(...)

    ELASTIC_STACK_VERSION: str = Field(...)
    ELASTICSEARCH_MCP_URL: str = Field(...)
    ELASTICSEARCH_MCP_AUTH_HEADER: Optional[str] = Field(...)
    ELASTIC_AGENT_BUILDER_MCP_NAMESPACES: List[str] = Field(...)
    ELASTIC_AGENT_BUILDER_INDEX_PATTERN: str = Field(...)

    PROMETHEUS_MCP_URL: str = Field(...)
    PROMETHEUS_MCP_SERVICE_LABEL: str = Field(...)
    PROMETHEUS_MCP_AUTH_HEADER: Optional[str] = Field(...)
    KUBERNETES_MCP_URL: Optional[str] = Field(...)
    VM_MCP_URL: Optional[str] = Field(...)

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
    SSH_ALLOWED_TARGETS: List[str] = Field(...)
    SSH_ALLOWED_SERVICES: List[str] = Field(...)
    VM_CPU_RECOVERY_THRESHOLD: float = Field(...)

    OIDC_ISSUER_URL: Optional[str] = Field(...)
    OIDC_AUDIENCE: Optional[str] = Field(...)
    OIDC_JWKS_URL: Optional[str] = Field(...)

    OFFLINE_IMAGE_REGISTRY: Optional[str] = Field(...)
    IMAGE_PULL_POLICY: str = Field(...)

    @field_validator("APP_ENV")
    @classmethod
    def validate_app_env(cls, value: str) -> str:
        normalized = str(value).strip().lower()
        if normalized not in {"development", "test", "production"}:
            raise ValueError("APP_ENV must be development, test, or production")
        return normalized

    @field_validator("KNOWLEDGE_PROVIDER")
    @classmethod
    def validate_knowledge_provider(cls, value: str) -> str:
        normalized = str(value).strip().lower()
        if normalized not in {"local_pgvector", "cognia"}:
            raise ValueError("KNOWLEDGE_PROVIDER must be local_pgvector or cognia")
        return normalized

    @field_validator("COGNIA_CONTEXT_PROFILE_ID", mode="before")
    @classmethod
    def parse_optional_cognia_context_profile_id(cls, value):
        if value is None or (isinstance(value, str) and not value.strip()):
            return None
        return value

    @field_validator("COGNIA_KNOWLEDGE_BASE_IDS")
    @classmethod
    def validate_cognia_knowledge_base_ids(cls, value: List[int]) -> List[int]:
        normalized: List[int] = []
        for raw in value:
            item = int(raw)
            if item <= 0:
                raise ValueError("COGNIA_KNOWLEDGE_BASE_IDS must contain positive IDs")
            if item not in normalized:
                normalized.append(item)
        return normalized

    @field_validator("LOG_ROTATION_MODE")
    @classmethod
    def validate_log_rotation_mode(cls, value: str) -> str:
        normalized = str(value).strip().lower()
        if normalized not in {"size", "time"}:
            raise ValueError("LOG_ROTATION_MODE must be 'size' or 'time'")
        return normalized

    @field_validator("LOG_LEVEL")
    @classmethod
    def validate_log_level(cls, value: str) -> str:
        normalized = str(value).strip().upper()
        if normalized not in {"CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG"}:
            raise ValueError("LOG_LEVEL must be CRITICAL, ERROR, WARNING, INFO, or DEBUG")
        return normalized

    @field_validator("ELASTIC_STACK_VERSION")
    @classmethod
    def validate_elastic_agent_builder_version(cls, value: str) -> str:
        parts = str(value).strip().split(".")
        try:
            major = int(parts[0])
            minor = int(parts[1]) if len(parts) > 1 else 0
        except (ValueError, IndexError) as exc:
            raise ValueError("ELASTIC_STACK_VERSION must be a semantic version such as 9.3.2") from exc
        if (major, minor) < (9, 2):
            raise ValueError("Elastic Agent Builder MCP requires Elastic Stack >= 9.2")
        return str(value).strip()

    @field_validator("ELASTICSEARCH_MCP_URL")
    @classmethod
    def validate_elastic_agent_builder_endpoint(cls, value: str) -> str:
        path = str(value).strip()
        if "/api/agent_builder/mcp" not in path:
            raise ValueError("ELASTICSEARCH_MCP_URL must target Kibana Agent Builder MCP /api/agent_builder/mcp")
        return path

    @field_validator("ELASTIC_AGENT_BUILDER_MCP_NAMESPACES")
    @classmethod
    def validate_elastic_namespaces(cls, value: List[str]) -> List[str]:
        normalized = [str(item).strip() for item in value if str(item).strip()]
        if "platform.core" not in normalized:
            raise ValueError("Elastic MCP namespaces must include platform.core for deterministic ES|QL Evidence")
        return normalized

    @model_validator(mode="after")
    def validate_cognia_contract(self) -> "Settings":
        if self.COGNIA_TIMEOUT_SECONDS <= 0:
            raise ValueError("COGNIA_TIMEOUT_SECONDS must be positive")
        if self.COGNIA_CONTEXT_PROFILE_ID is not None and self.COGNIA_CONTEXT_PROFILE_ID <= 0:
            raise ValueError("COGNIA_CONTEXT_PROFILE_ID must be positive when configured")

        if self.KNOWLEDGE_PROVIDER == "cognia":
            missing = [
                name
                for name, value in {
                    "COGNIA_BASE_URL": self.COGNIA_BASE_URL,
                    "COGNIA_CLIENT_ID": self.COGNIA_CLIENT_ID,
                    "COGNIA_CLIENT_SECRET": self.COGNIA_CLIENT_SECRET,
                }.items()
                if not str(value or "").strip()
            ]
            if not self.COGNIA_KNOWLEDGE_BASE_IDS:
                missing.append("COGNIA_KNOWLEDGE_BASE_IDS")
            if missing:
                raise ValueError("Cognia provider requires: " + ", ".join(missing))

        if self.APP_ENV == "production" and self.KNOWLEDGE_REQUIRE_GOVERNANCE_PRODUCTION:
            if self.KNOWLEDGE_PROVIDER != "cognia":
                raise ValueError("production governed knowledge requires KNOWLEDGE_PROVIDER=cognia")
            if urlparse(str(self.COGNIA_BASE_URL or "")).scheme != "https":
                raise ValueError("COGNIA_BASE_URL must use HTTPS in production")
            if not self.COGNIA_TLS_VERIFY:
                raise ValueError("COGNIA_TLS_VERIFY must be enabled in production")
        return self

    model_config = SettingsConfigDict(
        env_file=(".env.example", ".env"),
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore",
    )


settings = Settings()
