from typing import Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import text

from database import AsyncSessionLocal
from domain.contracts.logging import logger
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


def _agent_metric_items(
    findings: List[Dict[str, object]],
    invocations: List[Dict[str, object]],
    checkpoints: List[Dict[str, object]],
) -> List[Dict[str, object]]:
    """Merge durable facts without inferring a call from deduplicated findings.

    `findings` is historical per-incident evidence of completed analyses.
    `agent_invocation_completed` audit records count actual workflow calls
    only *since instrumentation began*. Older calls are not invented.
    Latest workflow checkpoints contribute coverage and collaboration detail.
    """
    combined: Dict[str, Dict[str, object]] = {}

    def row_for(name: object) -> Optional[Dict[str, object]]:
        key = str(name or "").strip()
        if not key:
            return None
        if key not in combined:
            combined[key] = {
                "agent_name": key, "scope": "durable_postgresql",
                "incident_count": 0, "finding_count": 0,
                "invocations": None, "successes": None, "failures": None,
                "average_confidence": None, "average_evidence_coverage": None,
                "handoffs": None, "conflicts": None, "human_reviews": None,
                "latest_analysis_at": None,
            }
        return combined[key]

    for item in findings:
        result = row_for(item.get("agent_name"))
        if result is None:
            continue
        result["incident_count"] = int(item.get("incident_count") or 0)
        result["finding_count"] = int(item.get("finding_count") or 0)
        value = item.get("average_confidence")
        result["average_confidence"] = round(float(value), 4) if value is not None else None
        last = item.get("latest_analysis_at")
        result["latest_analysis_at"] = last.isoformat() if hasattr(last, "isoformat") else last

    for item in invocations:
        result = row_for(item.get("agent_name"))
        if result is None:
            continue
        result["invocations"] = int(item.get("invocations") or 0)
        result["successes"] = int(item.get("successes") or 0)
        result["failures"] = int(item.get("failures") or 0)
        result["tracked_since"] = "agent_invocation_audit"
        if result["average_confidence"] is None and item.get("average_confidence") is not None:
            result["average_confidence"] = round(float(item["average_confidence"]), 4)
        if item.get("average_evidence_coverage") is not None:
            result["average_evidence_coverage"] = round(float(item["average_evidence_coverage"]), 4)
        for field in ("handoffs", "conflicts", "human_reviews"):
            result[field] = int(item.get(field) or 0)

    for item in checkpoints:
        result = row_for(item.get("agent_name"))
        if result is None:
            continue
        # Historical/latest checkpoint coverage is shown only when actual
        # validated AgentOutput values are stored there.
        if result["average_evidence_coverage"] is None and item.get("average_evidence_coverage") is not None:
            result["average_evidence_coverage"] = round(float(item["average_evidence_coverage"]), 4)
        if result["handoffs"] is None:
            result["handoffs"] = int(item.get("handoffs") or 0)
        if result["conflicts"] is None:
            result["conflicts"] = int(item.get("conflicts") or 0)
        if result["human_reviews"] is None:
            result["human_reviews"] = int(item.get("human_reviews") or 0)
    return sorted(combined.values(), key=lambda item: str(item["agent_name"]))


# Each source is durable. This read-only dashboard never runs Agents/LLMs.
_FINDING_METRICS_SQL = """
SELECT agent AS agent_name, COUNT(*) AS finding_count,
       COUNT(DISTINCT incident_id) AS incident_count,
       AVG(confidence) AS average_confidence,
       MAX(created_at) AS latest_analysis_at
FROM findings
WHERE agent IS NOT NULL
GROUP BY agent
"""

_INVOCATION_METRICS_SQL = """
SELECT metadata->>'agent_name' AS agent_name,
       COUNT(*) AS invocations,
       COUNT(*) FILTER (WHERE metadata->>'success' = 'true') AS successes,
       COUNT(*) FILTER (WHERE metadata->>'success' = 'false') AS failures,
       AVG(CASE WHEN jsonb_typeof(metadata->'confidence') = 'number'
                THEN (metadata->>'confidence')::double precision ELSE NULL END) AS average_confidence,
       AVG(CASE WHEN jsonb_typeof(metadata->'evidence_coverage') = 'number'
                THEN (metadata->>'evidence_coverage')::double precision ELSE NULL END) AS average_evidence_coverage,
       COALESCE(SUM(CASE WHEN jsonb_typeof(metadata->'handoffs') = 'number'
                         THEN (metadata->>'handoffs')::integer ELSE 0 END), 0) AS handoffs,
       COALESCE(SUM(CASE WHEN jsonb_typeof(metadata->'conflicts') = 'number'
                         THEN (metadata->>'conflicts')::integer ELSE 0 END), 0) AS conflicts,
       COUNT(*) FILTER (WHERE metadata->>'human_review' = 'true') AS human_reviews
FROM audit_events
WHERE event_type = 'agent_invocation_completed'
  AND metadata->>'agent_name' IS NOT NULL
GROUP BY metadata->>'agent_name'
"""

_CHECKPOINT_METRICS_SQL = """
SELECT finding.value->>'agent_name' AS agent_name,
       AVG(CASE WHEN jsonb_typeof(finding.value->'evidence_coverage') = 'number'
                THEN (finding.value->>'evidence_coverage')::double precision ELSE NULL END) AS average_evidence_coverage,
       COALESCE(SUM(CASE WHEN jsonb_typeof(finding.value->'handoff_agents') = 'array'
                         THEN jsonb_array_length(finding.value->'handoff_agents') ELSE 0 END), 0) AS handoffs,
       COALESCE(SUM(CASE WHEN jsonb_typeof(finding.value->'conflicting_evidence_ids') = 'array'
                         THEN jsonb_array_length(finding.value->'conflicting_evidence_ids') ELSE 0 END), 0) AS conflicts,
       COUNT(*) FILTER (WHERE finding.value->>'requires_human_review' = 'true') AS human_reviews
FROM workflow_checkpoints wc
CROSS JOIN LATERAL jsonb_array_elements(
    CASE WHEN jsonb_typeof(wc.state->'findings') = 'array'
         THEN wc.state->'findings' ELSE '[]'::jsonb END
) AS finding(value)
WHERE jsonb_typeof(finding.value) = 'object'
  AND finding.value->>'agent_name' IS NOT NULL
GROUP BY finding.value->>'agent_name'
"""


@router.get("/agents/metrics")
async def agent_metrics():
    """Durable cross-worker Agent history, not process-local zeroed counters.

    Historical finding counts are *incident analyses*, not true invocation
    counts. True workflow invocations become available only for calls that
    have been written to durable Audit with agent_invocation_completed.
    """
    try:
        async with AsyncSessionLocal() as session:
            findings = (await session.execute(text(_FINDING_METRICS_SQL))).mappings().all()
            invocations = (await session.execute(text(_INVOCATION_METRICS_SQL))).mappings().all()
            checkpoints = (await session.execute(text(_CHECKPOINT_METRICS_SQL))).mappings().all()
    except Exception as exc:
        logger.warning("agent_durable_metrics_unavailable", error_type=type(exc).__name__)
        raise HTTPException(status_code=503, detail="agent_durable_metrics_unavailable") from exc

    items = _agent_metric_items(
        [dict(x) for x in findings],
        [dict(x) for x in invocations],
        [dict(x) for x in checkpoints],
    )
    return {
        "items": items,
        "by_agent": {str(item["agent_name"]): item for item in items},
        "scope": "durable_postgresql",
        "invocation_policy": "tracked_workflow_audit_only; historical_incident_counts_from_findings",
    }
