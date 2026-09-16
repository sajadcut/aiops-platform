from typing import Dict, List, Optional

from fastapi import APIRouter, Depends

from agents.shared.registry import AgentRegistry
from agents.shared.telemetry import AgentTelemetry
from apps.security.auth import require_permission
from integrations.llm.base import LLMAdapter, LLMResponse

router = APIRouter(dependencies=[Depends(require_permission("read:incident"))])


class _CatalogOnlyLLMAdapter(LLMAdapter):
    """Non-executable adapter used only to construct analysis metadata safely.

    Agent constructors require an adapter object. The catalog endpoint must never
    initialize a real provider or perform inference, so every generation method
    fails closed if this metadata-only adapter is ever used outside construction.
    """

    @property
    def provider_name(self) -> str:
        return "catalog-only"

    async def generate(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        temperature: float = 0.7,
        max_tokens: int = 1000,
        **kwargs,
    ) -> LLMResponse:
        raise RuntimeError("catalog_only_adapter_cannot_generate")

    async def generate_with_messages(
        self,
        messages: List[Dict[str, str]],
        temperature: float = 0.7,
        max_tokens: int = 1000,
        **kwargs,
    ) -> LLMResponse:
        raise RuntimeError("catalog_only_adapter_cannot_generate")


@router.get("/agents/catalog")
async def agent_catalog():
    """Return the specialist catalog without requiring an operational LLM runtime.

    Catalog metadata is static/runtime configuration state used for routing and UI.
    Reading it must not depend on LLM provider credentials or availability because
    the endpoint never executes an Agent or grants write authority.
    """
    registry = AgentRegistry(_CatalogOnlyLLMAdapter())
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
