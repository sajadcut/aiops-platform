from typing import List, Optional

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    APP_NAME: str = "AI Ops NeoBankingOperation Platform"
    APP_VERSION: str = "0.1.0"
    DEBUG: bool = False
    HOST: str = "0.0.0.0"
    PORT: int = 8000

    DATABASE_URL: Optional[str] = Field(default="postgresql+asyncpg://user:pass@localhost:5432/aiops")
    DATABASE_POOL_SIZE: int = 10
    DATABASE_MAX_OVERFLOW: int = 20

    LLM_PROVIDER: str = "mock"
    LLM_API_KEY: Optional[str] = None
    LLM_MODEL: str = "gpt-4"

    LOG_LEVEL: str = "INFO"
    LOG_JSON: bool = False

    ZABBIX_URL: str = "http://localhost:8080"
    ZABBIX_USERNAME: str = "Admin"
    ZABBIX_PASSWORD: str = "zabbix"
    ELASTICSEARCH_HOSTS: List[str] = ["http://localhost:9200"]
    ELASTICSEARCH_USERNAME: Optional[str] = None
    ELASTICSEARCH_PASSWORD: Optional[str] = None
    PROMETHEUS_URL: str = "http://localhost:9090"

    INTERNAL_API_KEY: Optional[str] = None
    OIDC_ISSUER_URL: Optional[str] = None
    OIDC_AUDIENCE: Optional[str] = None
    OIDC_JWKS_URL: Optional[str] = None
    PGVECTOR_EXPECTED_DIMENSION: Optional[int] = None
    PGVECTOR_VALIDATE_ON_STARTUP: bool = True
    OFFLINE_IMAGE_REGISTRY: Optional[str] = None

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", case_sensitive=True, extra="ignore")


settings = Settings()
