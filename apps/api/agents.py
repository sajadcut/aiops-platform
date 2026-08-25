from fastapi import APIRouter, Depends

from agents.shared.registry import AgentRegistry
from apps.security.auth import require_permission
from integrations.llm.openai_compatible import configured_llm_adapter

router = APIRouter(dependencies=[Depends(require_permission("read:incident"))])


@router.get("/agents/catalog")
async def agent_catalog():
    """Return the enabled analysis-only specialist catalog.

    The endpoint intentionally exposes capability metadata only; it does not
    invoke agents and cannot execute operational changes.
    """
    registry = AgentRegistry(configured_llm_adapter())
    return {
        "items": [manifest.__dict__ for manifest in registry.manifests()],
        "execution_boundary": "agents_are_analysis_only",
        "enabled": registry.enabled_names(),
    }
