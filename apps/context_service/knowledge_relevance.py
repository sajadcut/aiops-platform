"""Cognia -> Incident relevance boundary shared by ingestion, agents and APIs.

A semantic hit is NOT evidence that a document belongs to a service.
Unscoped documents are quarantined unless the author explicitly marks them
cross-service. This gate never changes Cognia authorization or live identity.
"""
from __future__ import annotations

from typing import Any, Iterable, Mapping

from apps.context_service.knowledge_topology import KnowledgeTopologyResolver


_UNNAMED = frozenset({"", "unknown", "none", "null", "n/a", "unset"})
_GENERAL = frozenset({"general", "cross-service", "all-services", "global"})


def _service(value: Any) -> str:
    return str(value or "").strip().casefold().removesuffix(".service")


def _metadata(item: Mapping[str, Any]) -> Mapping[str, Any]:
    value = item.get("metadata")
    return value if isinstance(value, Mapping) else {}


def _declared_services(parsed: Mapping[str, Any], metadata: Mapping[str, Any]) -> set[str]:
    """Read explicit ownership only; never guess from free-text mentions."""
    values: list[Any] = [parsed.get("service")]
    for field in ("service", "service_name", "application", "services"):
        value = metadata.get(field)
        if isinstance(value, (list, tuple)):
            values.extend(value)
        elif value is not None:
            values.extend(value.split(",") if field == "services" and isinstance(value, str) else [value])
    return {name for value in values if (name := _service(value)) not in _UNNAMED}


def _generic(parsed: Mapping[str, Any], metadata: Mapping[str, Any], content: str) -> bool:
    # Cognia visibility scope=general is NOT an applicability declaration.
    value = str(metadata.get("applicability") or metadata.get("service_applicability") or "").strip().casefold()
    if value in _GENERAL:
        return True
    for line in content.splitlines()[:100]:
        key, separator, val = line.partition(":")
        if separator and key.strip().casefold() in {"applicability", "service applicability"}:
            return val.strip().casefold() in _GENERAL
    return False


def filter_service_knowledge(
    documents: Iterable[Mapping[str, Any]],
    *,
    expected_service: str | None,
    expected_fqdns: Iterable[str] | None = None,
    purpose: str = "incident",
) -> tuple[list[dict], dict]:
    """Fail closed for unowned and mismatched knowledge across ALL services.

    Service-owned knowledge must match the source/verified incident service.
    Where no service was named, exact source FQDN matching can guide read-only
    discovery. General guides require an explicit applicability declaration.
    No provider score, hostname coincidence or unstructured keyword suffices.
    """
    expected = _service(expected_service)
    known = expected not in _UNNAMED
    fqdns = {
        fqdn for value in (expected_fqdns or ())
        if (fqdn := KnowledgeTopologyResolver._normalize_fqdn(str(value or "")))
    }
    accepted: list[dict] = []
    rejected: list[dict] = []
    for item in documents:
        if not isinstance(item, Mapping):
            continue
        document = dict(item)
        content = str(document.get("content") or "")[:32768]
        parsed = KnowledgeTopologyResolver._parse_content(content)
        metadata = _metadata(document)
        owners = _declared_services(parsed, metadata)
        ref = str(document.get("source_id") or document.get("id") or "")[:160]
        doc_fqdn = KnowledgeTopologyResolver._normalize_fqdn(
            str(parsed.get("fqdn") or metadata.get("fqdn") or metadata.get("url") or "")
        )
        fqdn_match = bool(fqdns and doc_fqdn and doc_fqdn in fqdns)
        reason = None
        if not content.strip():
            reason = "empty_document"
        elif known and owners and owners != {expected}:
            reason = "document_service_conflicts_with_incident"
        elif known and doc_fqdn and fqdns and not fqdn_match:
            reason = "document_fqdn_conflicts_with_incident"
        elif not owners and not fqdn_match and not _generic(parsed, metadata, content):
            reason = "unscoped_document_not_verified_general"
        elif not known and owners and not fqdn_match:
            reason = "unbound_service_without_source_fqdn"
        if reason:
            rejected.append({
                "source_id": ref, "reason": reason,
                "declared_services": sorted(owners)[:8],
            })
        else:
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
        "policy": "explicit_service_or_exact_source_fqdn_or_declared_general",
    }
