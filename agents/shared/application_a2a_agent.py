from agents.shared.a2a_agent import A2AAgent, A2AAgentCard
from agents.application import ApplicationAgent
from agents.shared.base import AgentInput
from typing import Dict, Any

class ApplicationA2AAgent(A2AAgent):
    def __init__(self):
        card = A2AAgentCard(
            name="application",
            description="Application-level analysis",
            version="1.0.0",
            endpoint="http://localhost:8001/a2a/application",
            capabilities=["analyze_logs", "check_deployment"]
        )
        super().__init__(card)
        self._core = ApplicationAgent()

    async def handle_request(self, request: Dict[str, Any]) -> Dict[str, Any]:
        method = request.get("method")
        params = request.get("params", {})
        if method == "analyze":
            input_data = AgentInput(**params)
            result = await self._core.analyze(input_data)
            return {"success": True, "result": result.model_dump()}
        return {"success": False, "error": f"Method {method} not supported"}