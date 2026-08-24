from typing import Any, Dict, List


class ContextBuilder:
    """Normalizes an incoming incident context and preserves evidence refs."""

    def build(self, incident: Dict[str, Any], evidence: List[Dict[str, Any]], deployments: List[Dict[str, Any]] | None = None) -> Dict[str, Any]:
        deployments = deployments or []
        refs = [str(item.get("reference") or item.get("id")) for item in evidence if item.get("reference") or item.get("id")]
        return {
            "incident": incident,
            "service": incident.get("service"),
            "dependencies": incident.get("dependencies", []),
            "recent_deployments": deployments,
            "evidence": evidence,
            "evidence_refs": refs,
            "time_window": incident.get("time_window"),
        }
