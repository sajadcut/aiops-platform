"""Service-scoped relevance gate at the Cognia -> AIOps trust boundary.

Semantic relevance is not ownership: low-relevance or unrelated chunks
must never be promoted into an incident's topology or Agent guidance.
This does not edit or revoke Knowledge Base access on Cognia.
"""
from __future__ import annotations

from typing import Any, Iterable, Mapping

from apps.context_service.knowledge_topology import KnowledgeTopologyResolver


_UNNAMED = frozenset({"", "unknown", "none", "null", "n/a", "unset"})


def _service(value: Any) -> str:
    return str(value or "").strip().casefold().removesuffix(".service")


def filter_service_knowledge(
    documents: Iterable[Mapping[str, Any]],
    *,
    expected_service: str | None,
    purpose: str = "incident",
) -> tuple[list[dict], dict]:
    """Drop documents whose *declared owner service* contradicts the incident.

    Generic framework/runbook documents without an owner-service assertion
    remain eligible for LLM advice. They cannot set topology/owner fields:
    use the separately guarded topology resolver for that.
    """
    expected = _service(expected_service)
    known = expected not in _UNNAMED
    accepted: list[dict] = []
    rejected: list[dict] = []
    for item in documents:
        if not isinstance(item, Mapping):
            continue
        document = dict(item)
        content = str(document.get("content") or "")[:32768]
        parsed = KnowledgeTopologyResolver._parse_content(content)
        claim = _service(parsed.get("service"))
        ref = str(document.get("source_id") or document.get("id") or "")[:160]
        if known and claim not in _UNNAMED and claim != expected:
            rejected.append({
                "source_id": ref,
                "reason": "document_service_conflicts_with_incident",
                "declared_service": claim[:100],
            })
            continue
        accepted.append(document)
    status = "filtered_empty" if rejected and not accepted else (
        "filtered" if rejected else "accepted"
    )
    return accepted, {
        "purpose": purpose,
        "expected_service": expected if known else None,
        "returned_count": len(accepted) + len(rejected),
        "accepted_count": len(accepted),
        "rejected_count": len(rejected),
        "rejected": rejected[:12],
        "status": status,
        "policy": "declared_service_match_or_general",
    }
