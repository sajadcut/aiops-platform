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

    MEMORY_HYBRID_RETRIEVAL_ENABLED: bool = Field(...)
    MEMORY_RETRIEVAL_CANDIDATE_MULTIPLIER: int = Field(..., ge=2, le=20)
    MEMORY_RRF_K: int = Field(..., ge=1, le=1000)
    MEMORY_MAX_EMBEDDING_TEXT_CHARS: int = Field(..., ge=1000, le=100000)
    MEMORY_REUSE_FEEDBACK_ENABLED: bool = Field(...)

    COGNIA_BASE_URL: Optional[str] = Field(...)
    COGNIA_CLIENT_ID: Optional[str] = Field(...)
    COGNIA_CLIENT_SECRET: Optional[str] = Field(...)
    COGNIA_CLIENT_APPLICATION_ID: Optional[int] = Field(...)
    COGNIA_KNOWLEDGE_BASE_IDS: List[int] = Field(...)
    COGNIA_CONTEXT_PROFILE_ID: Optional[int] = Field(...)
    COGNIA_TIMEOUT_SECONDS: int = Field(...)

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
    MCP_BEARER_TOKEN: Optional[str] = Field(...)
    MCP_WRITE_BEARER_TOKEN: Optional[str] = Field(...)
    MCP_CLIENT_CERT_PATH: Optional[str] = Field(...)
    MCP_CLIENT_KEY_PATH: Optional[str] = Field(...)
    MCP_TIMEOUT_SECONDS: int = Field(...)
    MCP_SERVER_PROVIDER: str = Field(...)
    MCP_SERVER_REQUIRE_AUTH: bool = Field(...)

    ZABBIX_MCP_URL: str = Field(...)
    ZABBIX_MCP_SERVER_NAME: Optional[str] = Field(...)
    ZABBIX_MCP_AUTH_HEADER: Optional[str] = Field(...)
    ZABBIX_MCP_HOST_HEADER: Optional[str] = Field(...)

    JENKINS_MCP_URL: Optional[str] = Field(...)
    JENKINS_MCP_PROTOCOL_VERSION: str = Field(...)
    JENKINS_MCP_AUTH_HEADER: Optional[str] = Field(...)
    JENKINS_MCP_WRITE_AUTH_HEADER: Optional[str] = Field(...)
    JENKINS_MCP_EXPECTED_IDENTITY: Optional[str] = Field(...)
    JENKINS_MCP_ORIGIN: Optional[str] = Field(...)
    JENKINS_MCP_ENABLE_WRITES: bool = Field(...)

    ELASTIC_STACK_VERSION: str = Field(...)
    ELASTICSEARCH_MCP_URL: str = Field(...)
    ELASTICSEARCH_MCP_PROTOCOL_VERSION: str = Field(...)
    ELASTICSEARCH_MCP_AUTH_HEADER: Optional[str] = Field(...)
    ELASTICSEARCH_MCP_USERNAME: Optional[str] = Field(...)
    ELASTICSEARCH_MCP_PASSWORD: Optional[str] = Field(...)
    ELASTIC_AGENT_BUILDER_MCP_NAMESPACES: List[str] = Field(...)
    ELASTIC_AGENT_BUILDER_INDEX_PATTERN: str = Field(...)
    ELASTIC_ANOMALY_ACCEPT_INTERIM: bool = Field(...)
    ELASTIC_ANOMALY_CONTEXT_LOOKBACK_SECONDS: int = Field(..., ge=60, le=86400)
    ELASTIC_ANOMALY_CONTEXT_LOOKAHEAD_SECONDS: int = Field(..., ge=0, le=3600)
    ELASTIC_ANOMALY_JOB_SERVICE_MAP: Dict[str, str] = Field(...)

    PROMETHEUS_MCP_URL: str = Field(...)
    PROMETHEUS_MCP_PROTOCOL_VERSION: str = Field(...)
    PROMETHEUS_MCP_SERVICE_LABEL: str = Field(...)
    PROMETHEUS_MCP_AUTH_HEADER: Optional[str] = Field(...)
    PROMETHEUS_ALERT_CONTEXT_LOOKBACK_SECONDS: int = Field(..., ge=60, le=86400)
    PROMETHEUS_ALERT_CONTEXT_LOOKAHEAD_SECONDS: int = Field(..., ge=0, le=3600)
    KUBERNETES_MCP_URL: Optional[str] = Field(...)
    VM_MCP_URL: Optional[str] = Field(...)

    ELASTICSEARCH_HOSTS: List[str] = Field(...)
    ELASTICSEARCH_USERNAME: Optional[str] = Field(...)
    ELASTICSEARCH_PASSWORD: Optional[str] = Field(...)
    ELASTICSEARCH_TIMEOUT_SECONDS: int = Field(...)
    PROMETHEUS_URL: str = Field(...)
    PROMETHEUS_TIMEOUT_SECONDS: int = Field(...)
    KUBERNETES_API_URL: Optional[str] = Field(...)
    KUBERNETES_TOKEN: Optional[str] = Field(...)
    KUBERNETES_TOKEN_FILE: Optional[str] = Field(...)
    KUBERNETES_NAMESPACE: str = Field(...)
    KUBERNETES_TIMEOUT_SECONDS: int = Field(...)
    KUBERNETES_LOG_TAIL_LINES: int = Field(...)
    SSH_ENABLED: bool = Field(...)
    SSH_AUTH_MODE: str = Field(...)
    SSH_USERNAME: str = Field(...)
    SSH_PASSWORD: Optional[str] = Field(...)
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

    @field_validator("SSH_AUTH_MODE")
    @classmethod
    def validate_ssh_auth_mode(cls, value: str) -> str:
        normalized = str(value or "").strip().lower()
        if normalized not in {"key", "password"}:
            raise ValueError("SSH_AUTH_MODE must be key or password")
        return normalized

    @field_validator("COGNIA_CONTEXT_PROFILE_ID", "COGNIA_CLIENT_APPLICATION_ID", mode="before")
    @classmethod
    def parse_optional_cognia_ids(cls, value):
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
        normalized = str(value).strip()
        parsed = urlparse(normalized)
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.netloc:
            raise ValueError("ELASTICSEARCH_MCP_URL must use HTTP or HTTPS")
        path = parsed.path.rstrip("/")
        segments = [segment for segment in path.split("/") if segment]
        default_space = path == "/api/agent_builder/mcp"
        custom_space = (
            len(segments) == 5
            and segments[0] == "s"
            and bool(segments[1])
            and segments[2:] == ["api", "agent_builder", "mcp"]
        )
        if not (default_space or custom_space):
            raise ValueError(
                "ELASTICSEARCH_MCP_URL must target /api/agent_builder/mcp or /s/{space}/api/agent_builder/mcp"
            )
        return normalized

    @field_validator("ELASTICSEARCH_MCP_PROTOCOL_VERSION")
    @classmethod
    def validate_elastic_mcp_protocol_version(cls, value: str) -> str:
        normalized = str(value).strip()
        if normalized != "2024-11-05":
            raise ValueError(
                "ELASTICSEARCH_MCP_PROTOCOL_VERSION must be 2024-11-05 for the documented Elastic Agent Builder MCP contract"
            )
        return normalized

    @field_validator("ELASTICSEARCH_MCP_AUTH_HEADER")
    @classmethod
    def validate_elastic_mcp_auth_header(cls, value: Optional[str]) -> Optional[str]:
        normalized = str(value or "").strip()
        if normalized and not (
            normalized.startswith("ApiKey ")
            or normalized.startswith("Bearer ")
            or normalized.startswith("Basic ")
        ):
            raise ValueError("Elastic Agent Builder MCP authentication must use ApiKey, Bearer, or Basic Authorization")
        return normalized or None

    @model_validator(mode="after")
    def validate_elastic_mcp_authentication(self) -> "Settings":
        username = str(self.ELASTICSEARCH_MCP_USERNAME or "").strip()
        password_configured = self.ELASTICSEARCH_MCP_PASSWORD is not None and self.ELASTICSEARCH_MCP_PASSWORD != ""
        if bool(username) != bool(password_configured):
            raise ValueError(
                "ELASTICSEARCH_MCP_USERNAME and ELASTICSEARCH_MCP_PASSWORD must be configured together"
            )
        if ":" in username:
            raise ValueError("ELASTICSEARCH_MCP_USERNAME must not contain ':' when HTTP Basic authentication is used")
        if self.ELASTICSEARCH_MCP_AUTH_HEADER and username:
            raise ValueError(
                "Configure either ELASTICSEARCH_MCP_AUTH_HEADER or ELASTICSEARCH_MCP_USERNAME/ELASTICSEARCH_MCP_PASSWORD, not both"
            )
        return self

    @field_validator("ELASTIC_AGENT_BUILDER_MCP_NAMESPACES")
    @classmethod
    def validate_elastic_namespaces(cls, value: List[str]) -> List[str]:
        normalized = [str(item).strip() for item in value if str(item).strip()]
        if "platform.core" not in normalized:
            raise ValueError("Elastic MCP namespaces must include platform.core for deterministic ES|QL Evidence")
        return normalized

    @field_validator("ELASTIC_ANOMALY_JOB_SERVICE_MAP")
    @classmethod
    def validate_elastic_anomaly_job_service_map(cls, value: Dict[str, str]) -> Dict[str, str]:
        normalized: Dict[str, str] = {}
        for raw_job_id, raw_service in value.items():
            job_id = str(raw_job_id or "").strip()
            service = str(raw_service or "").strip()
            if not job_id or not service:
                raise ValueError("ELASTIC_ANOMALY_JOB_SERVICE_MAP keys and values must be non-empty")
            normalized[job_id] = service
        return normalized

    @field_validator("JENKINS_MCP_PROTOCOL_VERSION")
    @classmethod
    def validate_jenkins_mcp_protocol_version(cls, value: str) -> str:
        normalized = str(value).strip()
        if normalized != "2025-06-18":
            raise ValueError("JENKINS_MCP_PROTOCOL_VERSION must be 2025-06-18 for the supported Jenkins MCP plugin contract")
        return normalized

    @field_validator("JENKINS_MCP_AUTH_HEADER", "JENKINS_MCP_WRITE_AUTH_HEADER")
    @classmethod
    def validate_jenkins_basic_auth_header(cls, value: Optional[str]) -> Optional[str]:
        normalized = str(value or "").strip()
        if normalized and not normalized.startswith("Basic "):
            raise ValueError("Jenkins MCP authentication must use Authorization: Basic <base64(username:api-token)>")
        return normalized or None

    @field_validator("PROMETHEUS_MCP_PROTOCOL_VERSION")
    @classmethod
    def validate_prometheus_mcp_protocol_version(cls, value: str) -> str:
        normalized = str(value).strip()
        if normalized != "2025-11-25":
            raise ValueError(
                "PROMETHEUS_MCP_PROTOCOL_VERSION must be 2025-11-25 for the supported prometheus/prometheus-mcp v0.18.x contract"
            )
        return normalized

    @model_validator(mode="after")
    def validate_external_contracts(self) -> "Settings":
        jenkins_url = str(self.JENKINS_MCP_URL or "").strip()
        if jenkins_url:
            parsed = urlparse(jenkins_url)
            if parsed.scheme.lower() not in {"http", "https"} or not parsed.netloc:
                raise ValueError("JENKINS_MCP_URL must use HTTP or HTTPS")
            if not parsed.path.rstrip("/").endswith("/mcp-server/mcp"):
                raise ValueError("JENKINS_MCP_URL must target the Jenkins Streamable HTTP endpoint /mcp-server/mcp")
            if self.APP_ENV == "production" and not self.JENKINS_MCP_AUTH_HEADER:
                raise ValueError("Production Jenkins MCP requires JENKINS_MCP_AUTH_HEADER")
            if self.APP_ENV == "production" and not str(self.JENKINS_MCP_EXPECTED_IDENTITY or "").strip():
                raise ValueError("Production Jenkins MCP requires JENKINS_MCP_EXPECTED_IDENTITY for authenticated-principal verification")
        if self.JENKINS_MCP_ENABLE_WRITES and not jenkins_url:
            raise ValueError("JENKINS_MCP_ENABLE_WRITES requires JENKINS_MCP_URL")
        if self.JENKINS_MCP_ENABLE_WRITES and not self.JENKINS_MCP_WRITE_AUTH_HEADER:
            raise ValueError("JENKINS_MCP_ENABLE_WRITES requires JENKINS_MCP_WRITE_AUTH_HEADER")
        origin = str(self.JENKINS_MCP_ORIGIN or "").strip()
        if origin:
            parsed_origin = urlparse(origin)
            if parsed_origin.scheme.lower() not in {"http", "https"} or not parsed_origin.netloc:
                raise ValueError("JENKINS_MCP_ORIGIN must be an HTTP(S) Jenkins root URL")
        return self

    @model_validator(mode="after")
    def validate_cognia_contract(self) -> "Settings":
        if self.COGNIA_TIMEOUT_SECONDS <= 0:
            raise ValueError("COGNIA_TIMEOUT_SECONDS must be positive")
        if self.COGNIA_CONTEXT_PROFILE_ID is not None and self.COGNIA_CONTEXT_PROFILE_ID <= 0:
            raise ValueError("COGNIA_CONTEXT_PROFILE_ID must be positive when configured")
        if self.COGNIA_CLIENT_APPLICATION_ID is not None and self.COGNIA_CLIENT_APPLICATION_ID <= 0:
            raise ValueError("COGNIA_CLIENT_APPLICATION_ID must be positive when configured")

        # Cognia is the only Knowledge RAG provider. Development/test may load the
        # tracked non-secret template without real Cognia credentials; any attempted
        # retrieval remains explicitly misconfigured rather than using another RAG.
        if self.APP_ENV == "production":
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
                raise ValueError("Cognia RAG requires: " + ", ".join(missing))
            cognia_scheme = urlparse(str(self.COGNIA_BASE_URL or "")).scheme.lower()
            if cognia_scheme not in {"http", "https"}:
                raise ValueError("COGNIA_BASE_URL must use HTTP or HTTPS")
        return self

    model_config = SettingsConfigDict(
        env_file=(".env.example", ".env"),
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore",
    )


settings = Settings()
