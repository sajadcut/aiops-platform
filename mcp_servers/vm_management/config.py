from __future__ import annotations

from typing import Literal

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class VMManagementSettings(BaseSettings):
    """Runtime contract for the standalone VM MCP boundary."""

    HOST: str = "0.0.0.0"
    PORT: int = Field(default=8765, ge=1, le=65535)
    INVENTORY_PATH: str = "mcp_servers/vm_management/inventory.yml"
    READ_TOKEN: str = Field(default="", min_length=0)
    WRITE_TOKEN: str = Field(default="", min_length=0)
    REQUIRE_AUTH: bool = True
    WRITE_ENABLED: bool = False
    SSH_AUTH_MODE: Literal["key", "password"] = "key"
    SSH_CONNECT_TIMEOUT: int = Field(default=10, ge=1, le=120)
    SSH_COMMAND_TIMEOUT: int = Field(default=30, ge=1, le=600)
    SSH_KNOWN_HOSTS: str = ""
    SSH_STRICT_HOST_KEY_CHECKING: bool = True
    MAX_CONCURRENCY: int = Field(default=10, ge=1, le=200)
    SESSION_TTL_SECONDS: int = Field(default=900, ge=30, le=86400)

    model_config = SettingsConfigDict(
        env_prefix="VM_MCP_SERVER_",
        env_file=".env.vm-mcp",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    @classmethod
    def from_environment(cls) -> "VMManagementSettings":
        settings = cls()
        if settings.REQUIRE_AUTH and (not settings.READ_TOKEN or not settings.WRITE_TOKEN):
            raise ValueError("vm_mcp_auth_tokens_required")
        if settings.SSH_STRICT_HOST_KEY_CHECKING and not settings.SSH_KNOWN_HOSTS:
            raise ValueError("vm_mcp_known_hosts_required_when_strict")
        return settings
