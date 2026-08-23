from abc import ABC, abstractmethod
from typing import Dict, Any, Optional
import httpx
from pydantic import BaseModel

class A2AAgentCard(BaseModel):
    name: str
    description: str
    version: str
    endpoint: str
    capabilities: list[str]

class A2AAgent(ABC):
    def __init__(self, agent_card: A2AAgentCard):
        self.card = agent_card
        self._client = httpx.AsyncClient(timeout=30.0)

    @abstractmethod
    async def handle_request(self, request: Dict[str, Any]) -> Dict[str, Any]:
        pass

    async def send_request(self, target_url: str, request: Dict[str, Any]) -> Dict[str, Any]:
        payload = {
            "jsonrpc": "2.0",
            "method": "agent.call",
            "params": {"agent": self.card.name, "request": request},
            "id": 1
        }
        response = await self._client.post(target_url, json=payload)
        return response.json()