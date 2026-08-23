from app.agents.a2a_agent import A2AAgent, A2AAgentCard
from app.agents.infrastructure_agent import InfrastructureAgent
from app.agents.base import AgentInput
from typing import Dict, Any

class InfrastructureA2AAgent(A2AAgent):
    def __init__(self):
        card = A2AAgentCard(
            name="infrastructure",
            description="Infrastructure-level analysis",
            version="1.0.0",
            endpoint="http://localhost:8001/a2a/infrastructure",
            capabilities=["analyze_metrics", "check_resources"]
        )
        super().__init__(card)
        self._core = InfrastructureAgent()

    async def handle_request(self, request: Dict[str, Any]) -> Dict[str, Any]:
        method = request.get("method")
        params = request.get("params", {})
        if method == "analyze":
            input_data = AgentInput(**params)
            result = await self._core.analyze(input_data)
            return {"success": True, "result": result.model_dump()}
        return {"success": False, "error": f"Method {method} not supported"}