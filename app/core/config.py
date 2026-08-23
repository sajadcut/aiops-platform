from pydantic_settings import BaseSettings
from pydantic import Field
from typing import Optional, List

class Settings(BaseSettings):
    # Application
    APP_NAME: str = "AI Ops NeoBankingOperation Platform"
    APP_VERSION: str = "0.1.0"
    DEBUG: bool = False
    
    # Server
    HOST: str = "0.0.0.0"
    PORT: int = 8000
    
    # Database
    DATABASE_URL: Optional[str] = Field(
        default="postgresql+asyncpg://user:pass@localhost:5432/aiops",
        description="PostgreSQL connection string with asyncpg driver"
    )
    DATABASE_POOL_SIZE: int = 10
    DATABASE_MAX_OVERFLOW: int = 20
    
    # LLM
    LLM_PROVIDER: str = "mock"
    LLM_API_KEY: Optional[str] = None
    LLM_MODEL: str = "gpt-4"
    
    # Logging
    LOG_LEVEL: str = "INFO"
    LOG_JSON: bool = False

    # --- Zabbix ---
    ZABBIX_URL: str = "http://localhost:8080"
    ZABBIX_USERNAME: str = "Admin"
    ZABBIX_PASSWORD: str = "zabbix"

    # --- Elasticsearch ---
    ELASTICSEARCH_HOSTS: List[str] = ["http://localhost:9200"]
    ELASTICSEARCH_USERNAME: Optional[str] = None
    ELASTICSEARCH_PASSWORD: Optional[str] = None

    # --- Prometheus ---
    PROMETHEUS_URL: str = "http://localhost:9090"

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        case_sensitive = True
        # کلید طلایی: فیلدهای اضافی در .env را نادیده بگیر (جلوگیری از خطاهای مشابه)
        extra = "ignore"

# ایجاد یک نمونه singleton از تنظیمات
settings = Settings()