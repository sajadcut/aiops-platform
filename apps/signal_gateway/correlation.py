from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from typing import Any, Dict, Optional


_TOKEN_RE = re.compile(r"[^a-z0-9_.:-]+")


@dataclass(frozen=True)
class CorrelationIdentity:
    fingerprint: Optional[str]
    service: str
    signal_family: str
    scope: Dict[str, str]
    explicit: bool = False


def _token(value: Any) -> str:
    text = str(value or "").strip().lower()
    return _TOKEN_RE.sub("-", text).strip("-")


def signal_family(signal_type: str, summary: str = "") -> str:
    """Map source-specific alert names to a bounded operational family.

    Correlation must not use LLM/free-form semantic similarity. The mapping is
    intentionally conservative: only well-known operational symptom families
    are eligible for automatic cross-source merging.
    """
    text = f"{signal_type} {summary}".lower()
    patterns = (
        ("service_error", ("5xx", "http 500", "errorrate", "error_rate", "exception", "timeout", "connectiontimeout", "latency")),
        ("resource_pressure", ("highcpu", "high cpu", "cpu", "memory", "oom", "disk", "inode", "pressure")),
        ("kubernetes_lifecycle", ("crashloop", "probe", "pod restart", "rollout", "imagepull", "scheduling", "evicted")),
        ("availability", ("unavailable", "down", "service unavailable", "healthcheck", "health check", "unreachable")),
        ("security", ("security", "malware", "intrusion", "privilege", "credential", "suspicious")),
    )
    for family, needles in patterns:
        if any(needle in text for needle in needles):
            return family
    return "uncorrelated"


def build_correlation_identity(
    *,
    service: str,
    signal_type: str,
    summary: str,
    asset: Optional[Dict[str, Any]] = None,
    explicit_key: Optional[str] = None,
) -> CorrelationIdentity:
    normalized_service = _token(service)
    if explicit_key:
        normalized = _token(explicit_key)
        if not normalized:
            return CorrelationIdentity(None, normalized_service, "explicit", {}, True)
        digest = hashlib.sha256(f"explicit:{normalized}".encode()).hexdigest()
        return CorrelationIdentity(f"explicit:{digest}", normalized_service, "explicit", {}, True)

    family = signal_family(signal_type, summary)
    if not normalized_service or normalized_service == "unknown" or family == "uncorrelated":
        return CorrelationIdentity(None, normalized_service, family, {}, False)

    asset = dict(asset or {})
    # Host/pod/IP are intentionally excluded. Different observability sources
    # often report different hosts for the same service symptom. Prefer stable
    # service/workload scope that can be normalized across sources.
    scope: Dict[str, str] = {}
    for key in ("environment", "cluster", "namespace", "workload_kind", "workload", "business_service"):
        value = _token(asset.get(key))
        if value:
            scope[key] = value

    material = "|".join(
        [f"service={normalized_service}", f"family={family}"]
        + [f"{key}={scope[key]}" for key in sorted(scope)]
    )
    digest = hashlib.sha256(material.encode()).hexdigest()
    return CorrelationIdentity(f"v1:{digest}", normalized_service, family, scope, False)
