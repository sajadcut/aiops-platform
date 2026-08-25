from fastapi import APIRouter, Depends

from agents.shared.registry import AgentRegistry
from agents.shared.telemetry import AgentTelemetry
from apps.security.auth import require_permission
from integrations.llm.openai_compatible import configured_llm_adapter

router = APIRouter(dependencies=[Depends(require_permission("read:incident"))])


@router.get("/agents/catalog")
async def agent_catalog():
    """Return the enabled analysis-only specialist catalog."""
    registry = AgentRegistry(configured_llm_adapter())
    return {
        "items": [manifest.__dict__ for manifest in registry.manifests()],
        "execution_boundary": "agents_are_analysis_only",
        "enabled": registry.enabled_names(),
    }


@router.get("/agents/metrics")
async def agent_metrics():
    """Return process-local Agent observability counters.

    Durable per-incident decisions remain in Audit/Workflow state; these counters
    are runtime health signals suitable for dashboards/exporters.
    """
    return {"items": AgentTelemetry.snapshot(), "scope": "process_local_runtime"}
