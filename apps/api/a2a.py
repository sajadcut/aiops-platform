from fastapi import APIRouter, Depends, HTTPException

from agents.shared.base import AgentInput
from agents.shared.registry import AgentRegistry
from agents.triage import TriageAgent
from apps.security.auth import require_permission
from integrations.llm.openai_compatible import configured_llm_adapter

router = APIRouter(dependencies=[Depends(require_permission("read:incident"))])


@router.post("/a2a/{agent_name}")
async def a2a_request(agent_name: str, request: dict):
    """Governed in-process A2A analysis endpoint.

    A2A is analysis-only and cannot bypass Evaluator/Decision/Approval/Execution.
    """
    if request.get("method") != "analyze":
        raise HTTPException(status_code=400, detail="unsupported_a2a_method")
    params = request.get("params") or {}
    try:
        input_data = AgentInput(**params)
    except Exception as exc:
        raise HTTPException(status_code=422, detail="invalid_agent_input") from exc

    llm = configured_llm_adapter()
    if agent_name == "triage":
        agent = TriageAgent(llm)
    else:
        agent = AgentRegistry(llm).get(agent_name)
    if agent is None:
        raise HTTPException(status_code=404, detail="agent_not_enabled")

    result = await agent.analyze(input_data)
    return {
        "success": True,
        "agent": agent_name,
        "result": result.model_dump(mode="json"),
        "execution_boundary": "analysis_only",
    }
