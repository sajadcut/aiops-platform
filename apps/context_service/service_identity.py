"""Shared, evidence-grounded service identity policy.

Three distinct concepts must never be conflated:
- confirmed/reported identity (from structured monitoring or verified live data)
- knowledge/LLM hypotheses (non-authoritative)
- monitored host (not the affected application service)

This module is deliberately pure and never calls an LLM or MCP, mutates a
database, or authorizes actions. Both ingestion and context workflows use it.
"""
from __future__ import annotations

from typing import Any, Iterable, Mapping

from .knowledge_topology import KnowledgeTopologyResolver

_EMPTY = frozenset({"", "unknown", "unknown-service", "none", "null", "n/a", "na", "unset"})


class ServiceIdentityResolver:
    @staticmethod
    def known(value: Any) -> str | None:
        if not isinstance(value, str):
            return None
        value = value.strip()
        return value if value.lower() not in _EMPTY else None

    @classmethod
    def expected_fqdns(cls, *, summary: str | None, context: Mapping[str, Any] | None = None) -> list[str]:
        context = context if isinstance(context, Mapping) else {}
        # host/hostname may identify a Zabbix monitoring container, NOT the
        # endpoint whose service is affected. Don't use them as a knowledge key.
        components = [summary, context.get("url"), context.get("endpoint"), context.get("fqdn")]
        text = " ".join(str(x or "")[:1000] for x in components)
        return KnowledgeTopologyResolver.extract_fqdns(text)

    @classmethod
    def resolve(
        cls,
        *,
        source_service: str | None,
        live_asset: Mapping[str, Any] | None,
        knowledge_topology: Mapping[str, Any] | None,
        expected_fqdns: Iterable[str] = (),
        candidate_hypotheses: Iterable[Mapping[str, Any]] = (),
        live_service_verified: bool = False,
    ) -> dict[str, Any]:
        """Produce provenance plus a canonical service for non-executable display.

        The only knowledge-to-service promotion permitted is an exact domain
        match from the source notification. A knowledge-mapped identity remains
        suspected until independently validated, even when displayed/queried.
        """
        expected = list(expected_fqdns)
        live = dict(live_asset or {})
        declared = cls.known(source_service)
        observed = cls.known(live.get("service"))
        topology = dict(knowledge_topology or {})
        reconciliation = KnowledgeTopologyResolver.constrain_trigger_service(
            KnowledgeTopologyResolver.reconcile(live, topology),
            expected_fqdns=expected,
        )
        asset = dict(reconciliation.get("effective_asset") or {})
        verified = bool(live_service_verified and observed)
        conflicts = list(reconciliation.get("conflicts") or [])
        if declared and observed and declared.casefold() != observed.casefold():
            conflicts.append({
                "field": "service", "source": declared, "observed": observed,
                "kind": "source_vs_live_service",
            })
            # A disagreement is never silently resolved by the latest collector.
            verified = False
        if declared:
            name = declared
            status = "verified" if verified and observed and declared.casefold() == observed.casefold() else "reported"
            basis = "source_declared_service"
        elif observed:
            name = observed
            status = "verified" if verified else "observed"
            basis = "live_observed_service"
        elif reconciliation.get("service_identity_basis") == "source_fqdn_matches_knowledge":
            name = cls.known(asset.get("service")) or "unknown"
            status = "suspected" if name != "unknown" else "unknown"
            basis = "source_fqdn_matches_knowledge"
        else:
            name = "unknown"
            status = "unknown"
            basis = "no_verified_service_identity"

        if name != "unknown":
            asset["service"] = name
        else:
            asset["service"] = None

        hypothesis = None
        hint = cls.known(reconciliation.get("unverified_knowledge_service_hint"))
        if hint and hint.casefold() != name.casefold():
            hypothesis = {"service": hint, "origin": "cognia", "verified": False}
        for candidate in candidate_hypotheses:
            if not isinstance(candidate, Mapping):
                continue
            label = cls.known(candidate.get("service"))
            if label and label.casefold() != name.casefold() and hypothesis is None:
                hypothesis = {"service": label, "origin": "llm_hypothesis", "verified": False}
                break

        reconciliation["effective_asset"] = asset
        reconciliation["conflicts"] = conflicts
        reconciliation["service_identity_basis"] = basis
        reconciliation["requires_live_verification"] = (
            bool(reconciliation.get("requires_live_verification"))
            or status in {"suspected", "unknown"}
            or bool(conflicts)
        )
        asset["service_identity_status"] = status
        asset["service_identity_basis"] = basis
        asset["service_identity_unverified"] = status not in {"verified", "reported"} or bool(conflicts)
        asset["requires_live_verification"] = reconciliation["requires_live_verification"]
        identity = {
            "service": name,
            "status": status,
            "verified": status == "verified",
            "basis": basis,
            "suspected_service": hypothesis["service"] if hypothesis else None,
            "suspected_service_source": hypothesis["origin"] if hypothesis else None,
            "requires_more_evidence": status != "verified" or bool(conflicts),
            "conflicts": conflicts,
            "source_host": cls.known(live.get("hostname")),
            "knowledge_service_hint_blocked": bool(hint),
            # Confidence is intentionally not fabricated from a tag or LLM.
            "confidence": None,
        }
        return {"service": name, "service_identity": identity, "topology_context": reconciliation, "asset_context": asset}
