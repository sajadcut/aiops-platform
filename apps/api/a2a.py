from fastapi import APIRouter, Request
from agents.shared.triage_a2a_agent import TriageA2AAgent
from agents.shared.application_a2a_agent import ApplicationA2AAgent
from agents.shared.infrastructure_a2a_agent import InfrastructureA2AAgent

router = APIRouter()
agents = {
    "triage": TriageA2AAgent(),
    "application": ApplicationA2AAgent(),
    "infrastructure": InfrastructureA2AAgent()
}

@router.post("/a2a/{agent_name}")
async def a2a_request(agent_name: str, request: Request):
    if agent_name not in agents:
        return {"success": False, "error": "Agent not found"}
    data = await request.json()
    return await agents[agent_name].handle_request(data)