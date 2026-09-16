from __future__ import annotations

from typing import Any, Dict, List, Mapping, Optional, Tuple

from agents.kubernetes.pipeline import build_kubernetes_analysis as _pipeline_build_kubernetes_analysis
from agents.kubernetes.resource_analyzers import ANALYZERS, analyze_resource_evidence


def _merge_findings(result: Dict[str, Any], outputs: List[Dict[str, Any]]) -> None:
    merged: Dict[Tuple[str, str], Dict[str, Any]] = {}
    for finding in result.get("findings") or []:
        if not isinstance(finding, Mapping) or not finding.get("code"):
            continue
        key = (str(finding.get("code")), str(finding.get("resource_name") or ""))
        merged[key] = dict(finding)
    for output in outputs:
        for finding in output.get("findings") or []:
            if not isinstance(finding, Mapping) or not finding.get("code"):
                continue
            enriched = dict(finding)
            enriched.setdefault("resource_kind", output.get("kind"))
            enriched.setdefault("resource_name", output.get("name"))
            key = (str(enriched.get("code")), str(enriched.get("resource_name") or ""))
            if key not in merged:
                merged[key] = enriched
            else:
                existing = merged[key]
                existing["evidence_ids"] = list(dict.fromkeys(
                    [str(x) for x in (existing.get("evidence_ids") or []) + (enriched.get("evidence_ids") or []) if x]
                ))
    result["findings"] = list(merged.values())[:120]


def _update_handoffs(result: Dict[str, Any], outputs: List[Dict[str, Any]]) -> None:
    handoffs = [str(x) for x in result.get("handoff_candidates") or [] if x]
    for output in outputs:
        for finding in output.get("findings") or []:
            if not isinstance(finding, Mapping):
                continue
            target = finding.get("handoff")
            if target and target not in handoffs:
                handoffs.append(str(target))
    result["handoff_candidates"] = handoffs[:6]


def build_kubernetes_analysis(
    evidence: List[Mapping[str, Any]],
    *,
    service_name: Optional[str] = None,
    context: Optional[Mapping[str, Any]] = None,
) -> Dict[str, Any]:
    result = _pipeline_build_kubernetes_analysis(
        evidence,
        service_name=service_name,
        context=context,
    )
    outputs = analyze_resource_evidence(evidence)
    result["resource_stage_outputs"] = outputs
    result["resource_analyzer_registry"] = sorted(ANALYZERS)
    result["resource_analyzer_output_count"] = len(outputs)
    _merge_findings(result, outputs)
    _update_handoffs(result, outputs)
    result["diagnostic_stages"] = [
        "resource_object_normalization",
        "independent_resource_analyzers",
        "event_metric_log_timeline_correlation",
        "service_endpoint_pod_controller_node_storage_network_causal_chain",
        "cross_resource_deterministic_enrichment",
        "llm_synthesis_after_deterministic_analysis",
    ]
    return result
