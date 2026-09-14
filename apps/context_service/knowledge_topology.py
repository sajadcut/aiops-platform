from __future__ import annotations

import json
import re
from typing import Any, Dict, Iterable, List, Mapping, Optional
from urllib.parse import urlparse


class KnowledgeTopologyResolver:
    """Deterministic bridge from Cognia Knowledge chunks to asset-discovery hints.

    Only a small allowlist of topology fields is parsed. Knowledge can guide
    discovery, but live operational metadata remains authoritative. Identity
    fields sourced only from Knowledge must be live-verified before a write can
    rely on them; auxiliary fields such as owner enrich reasoning without
    turning an otherwise live-verified target into an execution blocker.
    """

    _KEY_ALIASES = {
        "url": "fqdn",
        "public_url": "fqdn",
        "endpoint": "fqdn",
        "fqdn": "fqdn",
        "domain": "fqdn",
        "service": "service",
        "service_name": "service",
        "application": "service",
        "app": "service",
        "platform": "platform",
        "runtime": "platform",
        "cluster": "cluster",
        "kubernetes_cluster": "cluster",
        "namespace": "namespace",
        "kubernetes_namespace": "namespace",
        "workload_kind": "workload_kind",
        "kind": "workload_kind",
        "workload": "workload",
        "deployment": "workload",
        "statefulset": "workload",
        "daemonset": "workload",
        "repository": "repository",
        "repo": "repository",
        "git_repository": "repository",
        "scm": "repository",
        "jenkins_job": "jenkins_job",
        "jenkins": "jenkins_job",
        "ci_job": "jenkins_job",
        "owner": "owner",
        "team": "owner",
    }
    _IDENTITY_FIELDS = (
        "service",
        "platform",
        "cluster",
        "namespace",
        "workload_kind",
        "workload",
    )
    _AUXILIARY_FIELDS = ("owner",)
    _ASSET_FIELDS = _IDENTITY_FIELDS + _AUXILIARY_FIELDS
    _UNKNOWN_VALUES = {"unknown", "none", "null", "n/a", "na", "unset", "undefined"}
    _FQDN_RE = re.compile(
        r"(?<![@A-Za-z0-9_-])(?:https?://)?"
        r"((?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+"
        r"[A-Za-z]{2,63})(?::\d+)?(?:/[^\s\"'<>]*)?",
        re.IGNORECASE,
    )
    _LINE_RE = re.compile(r"^\s*([A-Za-z0-9_. /-]{2,64})\s*[:=]\s*(.*?)\s*$")

    @classmethod
    def build_discovery_query(cls, incident: Mapping[str, Any]) -> str:
        service = cls._clean(incident.get("service"))
        summary = cls._clean(incident.get("summary"))
        context = incident.get("context")
        identifiers: List[str] = []
        if service and service.lower() not in cls._UNKNOWN_VALUES:
            identifiers.append(service)
        identifiers.extend(cls.extract_fqdns(summary or ""))
        if isinstance(context, Mapping):
            for key in ("url", "fqdn", "host", "hostname", "service", "service_name", "endpoint"):
                value = cls._clean(context.get(key))
                if not value or value.lower() in cls._UNKNOWN_VALUES:
                    continue
                if key in {"url", "fqdn", "host", "hostname", "endpoint"}:
                    identifiers.extend(cls.extract_fqdns(value))
                else:
                    identifiers.append(value)

        deduped: List[str] = []
        for value in identifiers:
            if value and value not in deduped:
                deduped.append(value)

        parts = ["service topology ownership deployment mapping"]
        if deduped:
            parts.append("identifiers: " + ", ".join(deduped[:8]))
        if summary:
            parts.append("incident: " + summary[:800])
        return " | ".join(parts)

    @classmethod
    def extract_fqdns(cls, text: str) -> List[str]:
        values: List[str] = []
        for match in cls._FQDN_RE.finditer(str(text or "")):
            fqdn = match.group(1).lower().rstrip(".")
            if fqdn and fqdn not in values:
                values.append(fqdn)
        return values

    @classmethod
    def resolve(
        cls,
        knowledge_results: Iterable[Mapping[str, Any]],
        *,
        expected_fqdns: Optional[Iterable[str]] = None,
    ) -> Dict[str, Any]:
        expected = {
            str(value).lower().rstrip(".")
            for value in (expected_fqdns or [])
            if str(value).strip()
        }
        fields: Dict[str, str] = {}
        field_sources: Dict[str, str] = {}
        conflicts: List[Dict[str, Any]] = []
        source_refs: List[str] = []
        skipped_mismatched_fqdns: List[str] = []

        for item in knowledge_results:
            if not isinstance(item, Mapping):
                continue
            parsed = cls._parse_content(str(item.get("content") or ""))
            if not parsed:
                continue
            candidate_fqdn = cls._normalize_field("fqdn", parsed.get("fqdn"))
            if expected and candidate_fqdn and candidate_fqdn not in expected:
                skipped_mismatched_fqdns.append(candidate_fqdn)
                continue

            source_ref = str(item.get("source_id") or item.get("id") or "cognia:unknown")
            if source_ref not in source_refs:
                source_refs.append(source_ref)

            for field, raw_value in parsed.items():
                value = cls._normalize_field(field, raw_value)
                if not value:
                    continue
                current = fields.get(field)
                if current is None:
                    fields[field] = value
                    field_sources[field] = source_ref
                elif not cls._same_value(field, current, value):
                    conflict = {
                        "field": field,
                        "selected": current,
                        "candidate": value,
                        "selected_source": field_sources.get(field),
                        "candidate_source": source_ref,
                        "kind": "knowledge_vs_knowledge",
                    }
                    if conflict not in conflicts:
                        conflicts.append(conflict)

        return {
            "fields": fields,
            "field_sources": field_sources,
            "source_refs": source_refs,
            "conflicts": conflicts,
            "skipped_mismatched_fqdns": skipped_mismatched_fqdns,
        }

    @classmethod
    def reconcile(cls, live_asset: Mapping[str, Any], topology: Mapping[str, Any]) -> Dict[str, Any]:
        live = dict(live_asset or {})
        knowledge_fields = dict(topology.get("fields") or {})
        merged = dict(live)
        provenance: Dict[str, str] = {}
        knowledge_filled_fields: List[str] = []
        conflicts: List[Dict[str, Any]] = list(topology.get("conflicts") or [])

        for field in cls._ASSET_FIELDS:
            live_value = cls._normalize_field(field, live.get(field))
            knowledge_value = cls._normalize_field(field, knowledge_fields.get(field))
            if live_value:
                merged[field] = live_value
                provenance[field] = "live"
                if knowledge_value and not cls._same_value(field, live_value, knowledge_value):
                    conflicts.append(
                        {
                            "field": field,
                            "live": live_value,
                            "knowledge": knowledge_value,
                            "knowledge_source": (topology.get("field_sources") or {}).get(field),
                            "kind": "live_vs_knowledge",
                        }
                    )
            elif knowledge_value:
                merged[field] = knowledge_value
                provenance[field] = "knowledge"
                knowledge_filled_fields.append(field)
            elif field in merged and cls._normalize_field(field, merged.get(field)) is None:
                # Do not expose placeholder values such as "unknown" as resolved
                # topology after reconciliation.
                merged[field] = "unknown" if field == "platform" else None

        knowledge_identity_fields = [
            field for field in knowledge_filled_fields if field in cls._IDENTITY_FIELDS
        ]
        requires_live_verification = bool(knowledge_identity_fields or conflicts)

        merged["field_provenance"] = provenance
        merged["knowledge_assisted"] = bool(knowledge_filled_fields)
        merged["requires_live_verification"] = requires_live_verification
        merged["topology_conflicts"] = conflicts

        return {
            "effective_asset": merged,
            "live_asset": live,
            "knowledge_topology": topology,
            "field_provenance": provenance,
            "knowledge_filled_fields": knowledge_filled_fields,
            "knowledge_identity_fields": knowledge_identity_fields,
            "conflicts": conflicts,
            "requires_live_verification": requires_live_verification,
            "execution_policy": "knowledge_identity_topology_must_be_live_verified_before_write",
            "deployment_hints": {
                key: knowledge_fields.get(key)
                for key in ("fqdn", "repository", "jenkins_job")
                if knowledge_fields.get(key)
            },
        }

    @classmethod
    def _parse_content(cls, content: str) -> Dict[str, str]:
        text = str(content or "").strip()
        if not text:
            return {}

        parsed_json = cls._parse_json(text)
        fields: Dict[str, str] = {}
        if isinstance(parsed_json, Mapping):
            cls._collect_mapping_fields(parsed_json, fields)

        for raw_line in text.splitlines():
            line = raw_line.strip().strip("`")
            if not line:
                continue
            match = cls._LINE_RE.match(line)
            if not match:
                continue
            key = cls._canonical_key(match.group(1))
            if key:
                value = cls._clean(match.group(2))
                if value and key not in fields:
                    fields[key] = value
        return fields

    @classmethod
    def _parse_json(cls, text: str) -> Any:
        candidate = text.strip()
        if candidate.startswith("```"):
            lines = candidate.splitlines()
            if len(lines) >= 3 and lines[-1].strip().startswith("```"):
                candidate = "\n".join(lines[1:-1]).strip()
        try:
            return json.loads(candidate)
        except (TypeError, ValueError):
            return None

    @classmethod
    def _collect_mapping_fields(cls, mapping: Mapping[str, Any], output: Dict[str, str]) -> None:
        for raw_key, raw_value in mapping.items():
            key = cls._canonical_key(str(raw_key))
            if key and not isinstance(raw_value, (Mapping, list, tuple)):
                value = cls._clean(raw_value)
                if value and key not in output:
                    output[key] = value
            normalized_key = cls._normalize_key(str(raw_key))
            if normalized_key in {"topology", "service_topology", "deployment", "runtime"} and isinstance(raw_value, Mapping):
                cls._collect_mapping_fields(raw_value, output)

    @classmethod
    def _canonical_key(cls, raw_key: str) -> Optional[str]:
        return cls._KEY_ALIASES.get(cls._normalize_key(raw_key))

    @staticmethod
    def _normalize_key(raw_key: str) -> str:
        return re.sub(r"_+", "_", re.sub(r"[^a-z0-9]+", "_", str(raw_key).strip().lower())).strip("_")

    @staticmethod
    def _clean(value: Any) -> Optional[str]:
        if value is None:
            return None
        text = str(value).strip().strip("\"'`")
        return text or None

    @classmethod
    def _normalize_field(cls, field: str, value: Any) -> Optional[str]:
        text = cls._clean(value)
        if not text:
            return None
        if field in cls._ASSET_FIELDS and text.lower() in cls._UNKNOWN_VALUES:
            return None
        if field == "fqdn":
            return cls._normalize_fqdn(text)
        if field == "platform":
            normalized = text.lower()
            if normalized in {"k8s", "kubernetes", "openshift", "ocp"}:
                return "kubernetes"
            if normalized in {"vm", "virtual_machine", "virtual machine", "server"}:
                return "vm"
            return normalized
        if field == "workload_kind":
            return text.lower()
        return text

    @staticmethod
    def _normalize_fqdn(value: str) -> Optional[str]:
        text = str(value or "").strip()
        if not text:
            return None
        parsed = urlparse(text if "://" in text else f"//{text}", scheme="")
        host = parsed.hostname
        if not host:
            host = text.split("/", 1)[0].split(":", 1)[0]
        host = host.strip().lower().rstrip(".")
        return host or None

    @classmethod
    def _same_value(cls, field: str, left: Any, right: Any) -> bool:
        lval = cls._normalize_field(field, left)
        rval = cls._normalize_field(field, right)
        if lval is None or rval is None:
            return lval == rval
        return lval.lower() == rval.lower()
