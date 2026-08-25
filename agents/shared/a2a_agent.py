from abc import ABC, abstractmethod
from typing import Any, Dict

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
    approval, evaluator, or execution boundaries.
    """

    def __init__(self, agent_card: A2AAgentCard):
        self.card = agent_card
        self._client = httpx.AsyncClient(timeout=settings.A2A_TIMEOUT_SECONDS)

    @abstractmethod
    async def handle_request(self, request: Dict[str, Any]) -> Dict[str, Any]:
        raise NotImplementedError

    async def send_request(self, target_url: str, request: Dict[str, Any]) -> Dict[str, Any]:
        if not target_url.startswith(("http://", "https://")):
            raise ValueError("invalid_a2a_target_url")
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
