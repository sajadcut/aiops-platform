from __future__ import annotations

from copy import deepcopy
from typing import Any, Dict, Iterable, List, Mapping


_SENSITIVE_PAYLOAD_KEYS = {"data", "stringData", "binaryData"}


def _resource_kind(item: Mapping[str, Any]) -> str:
    raw = item.get("raw_data") if isinstance(item.get("raw_data"), Mapping) else {}
    for candidate in (item.get("resource"), item.get("object"), raw.get("resource"), raw.get("object"), raw):
        if isinstance(candidate, Mapping) and candidate.get("kind"):
            return str(candidate.get("kind")).lower()
    return str(item.get("kind") or "").lower()


def _redact_payload(value: Any, *, protected: bool = False) -> Any:
    if isinstance(value, list):
        return [_redact_payload(item, protected=protected) for item in value[:40]]
    if not isinstance(value, dict):
        return value
    result: Dict[str, Any] = {}
    for key, current in list(value.items())[:100]:
        if protected and key in _SENSITIVE_PAYLOAD_KEYS:
            result[key] = "[REDACTED_KUBERNETES_PAYLOAD]"
            continue
        nested_kind = str(value.get("kind") or "").lower()
        nested_protected = protected or nested_kind in {"secret", "configmap"}
        result[str(key)] = _redact_payload(current, protected=nested_protected)
    return result


def safe_evidence_for_prompt(evidence: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Return a bounded-copy-friendly evidence set with Secret/ConfigMap payload values removed.

    This is intentionally Kubernetes-specific because generic prompt redaction cannot infer that
    a key named `data` is sensitive for a Secret/ConfigMap while harmless elsewhere.
    """
    safe: List[Dict[str, Any]] = []
    for item in evidence:
        if not isinstance(item, dict):
            continue
        copied = deepcopy(item)
        kind = _resource_kind(copied)
        copied = _redact_payload(copied, protected=kind in {"secret", "configmap"})
        safe.append(copied)
    return safe
