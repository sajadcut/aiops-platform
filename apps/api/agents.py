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


def _agent_metric_items(snapshot: Dict[str, Dict[str, object]]) -> List[Dict[str, object]]:
    """Normalize process-local telemetry into the dashboard/API list contract."""
    items: List[Dict[str, object]] = []
    for agent_name, raw in snapshot.items():
        row: Dict[str, object] = {"agent_name": agent_name, **raw}
        # Stable dashboard aliases while retaining the canonical telemetry fields.
        row["average_confidence"] = raw.get("avg_confidence", 0.0)
        row["average_evidence_coverage"] = raw.get("avg_evidence_coverage", 0.0)
        items.append(row)
    return items


@router.get("/agents/metrics")
async def agent_metrics():
    """Return process-local Agent observability counters.

    Durable per-incident decisions remain in Audit/Workflow state; these counters
    are runtime health signals suitable for dashboards/exporters. ``items`` is a
    stable array for UI consumers; ``by_agent`` preserves the keyed snapshot for
    programmatic consumers and diagnostics.
    """
    snapshot = AgentTelemetry.snapshot()
    return {
        "items": _agent_metric_items(snapshot),
        "by_agent": snapshot,
        "scope": "process_local_runtime",
    }
