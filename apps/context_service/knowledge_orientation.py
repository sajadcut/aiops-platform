"""Bounded, advisory Cognia service-profile context for incident triage.

Cognia documents can suggest technology, dependencies, and config locations,
but NEVER provide an executable path, VM target, command, or current health.
Only relevance-filtered documents should reach build_orientation().
"""
from __future__ import annotations

import re
from typing import Any, Mapping

from domain.contracts.redaction import redact_text

_SERVICE = re.compile(r"^[A-Za-z0-9@_.:-]{2,128}$")
_HINT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_. +#/-]{0,59}$")
_ABSOLUTE_CONFIG = re.compile(r"^/(?:[A-Za-z0-9_.+-]+/){1,14}[A-Za-z0-9_.+-]{1,80}$")
_DENIED_ROOTS = ("/etc/shadow", "/etc/ssh/", "/etc/ssl/", "/etc/pki/",
                 "/etc/security/", "/opt/secrets/", "/run/", "/proc/",
                 "/sys/", "/dev/")
_ALLOWED_ROOTS = ("/etc/", "/opt/", "/data/", "/srv/", "/usr/local/")
_CONFIG_EXTS = (".json", ".yaml", ".yml", ".toml", ".ini", ".properties",
                ".xml", ".config", ".conf", ".cfg", ".cnf", ".hcl")


def service_profile_query(service: str | None, summary: str | None) -> str | None:
    """Ask for stack/config/dependency knowledge, not an LLM-generated command."""
    identity = str(service or "").strip().removesuffix(".service")
    if not _SERVICE.fullmatch(identity) or identity.casefold() in {"unknown", "none", "null"}:
        return None
    symptom = redact_text(str(summary or "").replace("\n", " "))[:240]
    return (
        f"Service: {identity} | service architecture technology runtime framework "
        "Java Tomcat .NET Python Go node Kubernetes systemd ExecStart WorkingDirectory "
        "deployment owner application configuration file location appsettings "
        "application.yml properties XML TOML environment source "
        "upstream downstream dependency database Redis ActiveMQ RabbitMQ Kafka "
        "HTTP API URL network endpoint connection troubleshooting"
        + (f" | incident symptom: {symptom}" if symptom else "")
    )[:850]


def _hint(value: Any) -> str | None:
    text = str(value or "").strip()
    return text if _HINT.fullmatch(text) else None


def _config_path(value: Any) -> str | None:
    text = str(value or "").strip().strip('"').strip("'")
    if (not _ABSOLUTE_CONFIG.fullmatch(text)
            or not text.startswith(_ALLOWED_ROOTS)
            or text.startswith(_DENIED_ROOTS)
            or not text.casefold().endswith(_CONFIG_EXTS)
            or ".." in text.split("/")):
        return None
    return text


def build_orientation(documents: list[dict], *, expected_service: str | None) -> dict:
    """Extract structural hints only from explicitly service-owned documents.

    Unowned *general* guides can inform LLM reasoning through the normal
    knowledge channel; they do not identify this service's runtime or files.
    """
    service = str(expected_service or "").strip().casefold().removesuffix(".service")
    hints: list[dict] = []
    refs: list[str] = []
    for doc in documents[:12]:
        if not isinstance(doc, dict):
            continue
        ref = str(doc.get("source_id") or doc.get("id") or "")[:160]
        if not ref:
            continue
        refs.append(ref)
        metadata = doc.get("metadata")
        metadata = metadata if isinstance(metadata, Mapping) else {}
        # Keep only claims explicitly owned by this exact service.
        from apps.context_service.knowledge_relevance import _declared_services
        from apps.context_service.knowledge_topology import KnowledgeTopologyResolver
        content = str(doc.get("content") or "")[:6000]
        parsed = KnowledgeTopologyResolver._parse_content(content)
        if not service or _declared_services(parsed, metadata) != {service}:
            continue
        candidates: list[tuple[str, Any]] = []
        for field in ("runtime", "technology", "framework", "platform", "config_path",
                      "config_file", "configuration_file", "dependency"):
            if field in metadata:
                candidates.append((field, metadata[field]))
        for line in content.splitlines()[:80]:
            match = re.match(
                r"^\s*(runtime|technology|framework|platform|config(?:uration)?"
                r"[ _-]?(?:file|path)|dependency)\s*:\s*(.{1,240})$",
                line, re.I,
            )
            if match:
                field = re.sub(r"[ -]", "_", match.group(1).lower())
                candidates.append((field, match.group(2)))
        for field, raw in candidates:
            kind = ("config_path" if ("config" in field and
                                      ("path" in field or "file" in field))
                    else field)
            value = _config_path(raw) if kind == "config_path" else _hint(raw)
            if not value or kind not in {
                "runtime", "technology", "framework", "platform",
                "dependency", "config_path",
            }:
                continue
            item = {"kind": kind, "value": value, "source_ref": ref,
                    "verified": False, "authority": "cognia_advisory_only"}
            if item not in hints:
                hints.append(item)
            if len(hints) >= 12:
                break
        if len(hints) >= 12:
            break
    return {
        "status": "hints_found" if hints else "no_service_owned_structural_hints",
        "hints": hints[:12], "source_refs": list(dict.fromkeys(refs))[:12],
        "read_only": True, "counts_as_live_evidence": False,
        "execution_authority": False, "requires_live_verification": True,
        "policy": "cognia_hints_never_choose_mcp_targets_or_config_files",
    }
