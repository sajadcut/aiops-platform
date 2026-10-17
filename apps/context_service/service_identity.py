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
    def split_conflicts(conflicts: Any) -> tuple[list[dict], list[dict]]:
        """Keep Cognia disagreements as evidence, never as executable authority.

        A Knowledge-only mismatch is a hypothesis about topology, not
        conflicting live/service-alert identity. Unknown conflict kinds and
        source-vs-live disagreements remain blocking (fail closed).
        """
        blocking: list[dict] = []
        advisory: list[dict] = []
        if not isinstance(conflicts, list):
            return ([{"kind": "identity_conflicts_malformed"}], []) if conflicts else ([], [])
        for item in conflicts:
            if not isinstance(item, dict):
                blocking.append({"kind": "identity_conflict_malformed"})
            elif item.get("kind") in {"live_vs_knowledge", "knowledge_vs_knowledge"}:
                advisory.append(item)
            else:
                blocking.append(item)
        return blocking, advisory

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

    @staticmethod
    def verified_runtime_alias_matches(
        reported_service: str, runtime_service: str,
        context: Mapping[str, Any] | None, evidence: Iterable[Mapping[str, Any]],
    ) -> bool:
        """Permit an alert-label/runtime-name mismatch only with direct VM evidence.

        A mutable alert, RAG hit, or alias setting is never sufficient alone.
        The persisted association has to match an actual successful, typed,
        same-incident VM service_status observation and configured alias.
        """
        reported = str(reported_service or "").strip().casefold().removesuffix(".service")
        runtime = str(runtime_service or "").strip().casefold().removesuffix(".service")
        if not reported or not runtime:
            return False
        if reported == runtime:
            return True
        ctx = context if isinstance(context, Mapping) else {}
        mapping = ctx.get("verified_runtime_mapping")
        if not isinstance(mapping, Mapping):
            return False
        if (str(mapping.get("source_service") or "").casefold() != reported
                or str(mapping.get("runtime_service") or "").casefold() != runtime
                or mapping.get("verification") != "vm_mcp_service_status"):
            return False
        target = str(mapping.get("target") or "").strip().casefold()
        ref = str(mapping.get("evidence_reference") or "")
        if not target or not ref:
            return False
        from domain.contracts.config import settings
        aliases = settings.ELASTIC_SERVICE_DISCOVERY_ALIASES or {}
        if not isinstance(aliases, dict):
            return False
        configured = any(
            (str(key).casefold() == reported and isinstance(values, list)
             and any(str(value).casefold() == runtime for value in values))
            or (str(key).casefold() == runtime and isinstance(values, list)
                and any(str(value).casefold() == reported for value in values))
            for key, values in aliases.items()
        )
        if not configured:
            return False
        for item in evidence:
            if not isinstance(item, Mapping) or item.get("source") != "vm_mcp":
                continue
            if str(item.get("reference") or "") != ref:
                continue
            raw = item.get("raw_data")
            if (isinstance(raw, Mapping) and raw.get("diagnostic") == "service_status"
                    and raw.get("success") is True
                    and str(raw.get("target") or "").strip().casefold() == target
                    and str(raw.get("service") or "").strip().casefold().removesuffix(".service") == runtime
                    and str(raw.get("source_service_label") or "").strip().casefold().removesuffix(".service") == reported
                    and str(raw.get("load_state") or "").lower() == "loaded"):
                return True
        return False

    @staticmethod
    def runtime_name_from_verified_mapping(
        reported_service: str, context: Mapping[str, Any] | None,
        evidence: Iterable[Mapping[str, Any]],
    ) -> str:
        """Return a case-preserved VM runtime unit only with same-incident proof.

        The original alert's label is retained in incident.service; it must
        never be lowercased or used as an arbitrary systemctl unit by live
        reads when a verified, explicitly configured runtime mapping exists.
        """
        reported = str(reported_service or "").strip()
        ctx = context if isinstance(context, Mapping) else {}
        mapping = ctx.get("verified_runtime_mapping")
        if isinstance(mapping, Mapping):
            canonical = str(mapping.get("runtime_service") or "").strip()
            if (canonical and
                    ServiceIdentityResolver.verified_runtime_alias_matches(
                        reported, canonical, ctx, evidence)):
                return canonical
        return reported

    @classmethod
    def independently_verified(
        cls,
        *,
        expected_service: str | None,
        expected_target: str | None,
        evidence: Iterable[Mapping[str, Any]],
    ) -> bool:
        """Require a direct successful read from the exact approved asset.

        Excludes RAG, Agent prose, source alerts, arbitrary process lists,
        unavailable MCP calls and checks made against unrelated VMs.
        """
        service = cls.known(expected_service)
        target = cls.known(expected_target)
        if not service or not target:
            return False
        for item in evidence:
            if not isinstance(item, Mapping) or item.get("source") not in {"vm_mcp", "vm_ssh"}:
                continue
            raw = item.get("raw_data")
            if not isinstance(raw, Mapping):
                continue
            if str(raw.get("diagnostic") or "") != "service_status":
                continue
            if raw.get("success") is False or raw.get("supported") is False or raw.get("error"):
                continue
            if str(raw.get("target") or "").strip().casefold() != target.casefold():
                continue
            if str(raw.get("service") or "").strip().casefold() == service.casefold():
                return True
        return False

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
        knowledge_service = cls.known((topology.get("fields") or {}).get("service"))
        knowledge_fqdn = KnowledgeTopologyResolver._normalize_fqdn(
            str((topology.get("fields") or {}).get("fqdn") or "")
        )
        matches_source = bool(knowledge_service and knowledge_fqdn and any(
            KnowledgeTopologyResolver._normalize_fqdn(str(value)) == knowledge_fqdn
            for value in expected
        ))
        if declared:
            name = declared
            status = "verified" if verified and observed and declared.casefold() == observed.casefold() else "reported"
            basis = "source_declared_service"
        elif observed and matches_source and observed.casefold() == knowledge_service.casefold():
            # The independent read agrees with a source-linked domain. Still
            # classify as observed, NOT confirmed causal ownership.
            name = observed
            status = "observed"
            basis = "live_observed_service"
        elif matches_source and not observed:
            name = knowledge_service
            status = "suspected"
            basis = "source_fqdn_matches_knowledge"
        elif observed:
            # A stopped nginx daemon discovered during investigation of an
            # unrelated memory alert is *not* the alert's named service.
            name = "unknown"
            status = "unknown"
            basis = "live_service_unlinked_to_alert"
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
        if observed and name == "unknown":
            hypothesis = {"service": observed, "origin": "mcp_observation", "verified": False}
        if matches_source and knowledge_service and name == "unknown":
            hypothesis = {"service": knowledge_service, "origin": "cognia", "verified": False}
        if hint and hint.casefold() != name.casefold() and hypothesis is None:
            hypothesis = {"service": hint, "origin": "cognia", "verified": False}
        for candidate in candidate_hypotheses:
            if not isinstance(candidate, Mapping):
                continue
            label = cls.known(candidate.get("service"))
            if label and label.casefold() != name.casefold() and hypothesis is None:
                hypothesis = {"service": label, "origin": "llm_hypothesis", "verified": False}
                break

        blocking_conflicts, advisory_conflicts = cls.split_conflicts(conflicts)
        reconciliation["effective_asset"] = asset
        reconciliation["conflicts"] = conflicts
        reconciliation["blocking_identity_conflicts"] = blocking_conflicts
        reconciliation["advisory_knowledge_conflicts"] = advisory_conflicts
        if name == "unknown" and observed:
            provenance = dict(reconciliation.get("field_provenance") or {})
            provenance["service"] = "unlinked_live_observation"
            reconciliation["field_provenance"] = provenance
            asset["field_provenance"] = {**dict(asset.get("field_provenance") or {}), **provenance}
        # Preserve the auditable legacy topology reason separately from the
        # canonical identity's (more general) unknown-state reason.
        reconciliation["service_identity_basis"] = (
            "unverified_knowledge_hint_blocked"
            if basis == "no_verified_service_identity" and hint else basis
        )
        reconciliation["requires_live_verification"] = (
            bool(reconciliation.get("requires_live_verification"))
            or status in {"suspected", "unknown"}
            or bool(conflicts)
        )
        asset["service_identity_status"] = status
        asset["service_identity_basis"] = basis
        asset["service_identity_unverified"] = status not in {"verified", "reported"} or bool(blocking_conflicts)
        asset["requires_live_verification"] = reconciliation["requires_live_verification"]
        identity = {
            "service": name,
            "status": status,
            "verified": status == "verified",
            "basis": basis,
            "suspected_service": hypothesis["service"] if hypothesis else None,
            "suspected_service_source": hypothesis["origin"] if hypothesis else None,
            "requires_more_evidence": status != "verified" or bool(blocking_conflicts),
            "conflicts": conflicts,
            "blocking_conflicts": blocking_conflicts,
            "advisory_knowledge_conflicts": advisory_conflicts,
            "source_host": cls.known(live.get("hostname")),
            "knowledge_service_hint_blocked": bool(hint),
            # Confidence is intentionally not fabricated from a tag or LLM.
            "confidence": None,
        }
        return {"service": name, "service_identity": identity, "topology_context": reconciliation, "asset_context": asset}
