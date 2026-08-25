from abc import ABC, abstractmethod
from typing import Any, Dict
from urllib.parse import urlparse

import httpx
from pydantic import BaseModel, Field

from domain.contracts.config import settings


class A2AAgentCard(BaseModel):
    name: str
    description: str
    version: str
    endpoint: str
    capabilities: list[str] = Field(default_factory=list)


class A2AAgent(ABC):
    """Authenticated, bounded transport for optional agent-to-agent RPC.

    A2A is coordination only. Remote responses never bypass local policy,
    approval, evaluator, or execution boundaries. Targets are restricted to a
    centrally configured origin allowlist before credentials are attached.
    """

    def __init__(self, agent_card: A2AAgentCard):
        self.card = agent_card
        self._client = httpx.AsyncClient(timeout=settings.A2A_TIMEOUT_SECONDS)

    @abstractmethod
    async def handle_request(self, request: Dict[str, Any]) -> Dict[str, Any]:
        raise NotImplementedError

    @staticmethod
    def _origin(url: str) -> str:
        parsed = urlparse(url)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise ValueError("invalid_a2a_target_url")
        if parsed.username or parsed.password:
            raise ValueError("a2a_userinfo_forbidden")
        return f"{parsed.scheme.lower()}://{parsed.netloc.lower()}"

    @classmethod
    def _validate_target(cls, target_url: str) -> str:
        origin = cls._origin(target_url)
        parsed = urlparse(target_url)
        if settings.A2A_REQUIRE_HTTPS and parsed.scheme.lower() != "https":
            raise ValueError("a2a_https_required")
        allowed_origins = {cls._origin(value) for value in settings.A2A_ALLOWED_TARGETS if str(value).strip()}
        if origin not in allowed_origins:
            raise ValueError("a2a_target_not_allowlisted")
        return origin

    async def send_request(self, target_url: str, request: Dict[str, Any]) -> Dict[str, Any]:
        self._validate_target(target_url)
        payload = {
            "jsonrpc": "2.0",
            "method": "agent.call",
            "params": {"agent": self.card.name, "request": request},
            "id": 1,
        }
        headers = {"Content-Type": "application/json"}
        if settings.INTERNAL_API_KEY:
            headers["X-API-Key"] = settings.INTERNAL_API_KEY
        response = await self._client.post(target_url, json=payload, headers=headers)
        response.raise_for_status()
        data = response.json()
        if not isinstance(data, dict) or data.get("jsonrpc") not in {None, "2.0"}:
            raise RuntimeError("invalid_a2a_response")
        if data.get("error"):
            raise RuntimeError(f"a2a_remote_error:{data['error']}")
        return data

    async def close(self) -> None:
        await self._client.aclose()
