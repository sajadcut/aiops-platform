from fastapi import APIRouter, Depends

from agents.shared.registry import AgentRegistry
from agents.shared.telemetry import AgentTelemetry
from apps.security.auth import require_permission

router = APIRouter(dependencies=[Depends(require_permission("read:incident"))])


@router.get("/agents/catalog")
async def agent_catalog():
    """Return the specialist catalog without requiring an operational LLM adapter.

    Catalog metadata is static/runtime configuration state used for routing and UI.
    Reading it must not depend on LLM provider credentials or availability because
    the endpoint never executes an Agent or grants write authority.
    """
    registry = AgentRegistry()
    manifests = registry.manifests()
    return {
        "items": [manifest.__dict__ for manifest in manifests],
        "execution_boundary": "agents_are_analysis_only",
        "enabled": registry.enabled_names(),
        "known": registry.known_names(),
        "catalog_status": "ready",
    }


@router.get("/agents/metrics")
async def agent_metrics():
    """Return process-local Agent observability counters.

    Durable per-incident decisions remain in Audit/Workflow state; these counters
    are runtime health signals suitable for dashboards/exporters.
    """
    return {"items": AgentTelemetry.snapshot(), "scope": "process_local_runtime"}
