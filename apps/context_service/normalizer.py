from typing import Any, Dict, Iterable, List
from apps.context_service.source_policy import DEFAULT_EVIDENCE_POLICY

def normalize_evidence(items: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    result: List[Dict[str, Any]] = []
    for item in items:
        source = str(item.get("source", "unknown"))
        confidence = float(item.get("confidence", 1.0))
        if not DEFAULT_EVIDENCE_POLICY.allows(source, confidence):
            continue
        result.append({
            "id": str(item.get("id") or item.get("reference") or "unknown"),
            "type": str(item.get("type", "unknown")),
            "source": source,
            "reference": str(item.get("reference") or item.get("id") or ""),
            "confidence": confidence,
            "raw_data": item.get("raw_data", {}),
        })
    return result
