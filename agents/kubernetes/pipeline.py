from __future__ import annotations

from copy import deepcopy
from typing import Any, Dict, Iterable, List, Mapping, Optional, Tuple

from agents.kubernetes.engine import build_kubernetes_analysis as _base_build_kubernetes_analysis


_CONTROLLER_KINDS = {"deployment", "replicaset", "statefulset", "daemonset", "job", "cronjob"}


def _raw(item: Mapping[str, Any]) -> Mapping[str, Any]:
    value = item.get("raw_data")
    return value if isinstance(value, Mapping) else {}


def _resource(item: Mapping[str, Any]) -> Mapping[str, Any]:
    raw = _raw(item)
    for value in (item.get("resource"), item.get("object"), raw.get("resource"), raw.get("object"), raw):
        if isinstance(value, Mapping) and (value.get("kind") or value.get("apiVersion") or value.get("metadata") or value.get("spec") or value.get("status")):
            return value
    return {}


def _kind(resource: Mapping[str, Any]) -> str:
    return "".join(ch for ch in str(resource.get("kind") or "").lower() if ch.isalpha())


def _eid(item: Mapping[str, Any], index: int) -> str:
    value = item.get("evidence_id") or item.get("id") or item.get("reference") or item.get("source_id")
    return str(value) if value not in (None, "") else f"anonymous:{index}"


def _metadata(resource: Mapping[str, Any]) -> Mapping[str, Any]:
    value = resource.get("metadata")
    return value if isinstance(value, Mapping) else {}


def _status(resource: Mapping[str, Any]) -> Mapping[str, Any]:
    value = resource.get("status")
    return value if isinstance(value, Mapping) else {}


def _event_text(item: Mapping[str, Any]) -> str:
    raw = _raw(item)
    parts = [
        item.get("message"), item.get("reason"), raw.get("message"), raw.get("reason"),
    ]
    return " ".join(str(value) for value in parts if value not in (None, "")).lower()


def _object_safe_evidence(evidence: List[Mapping[str, Any]]) -> List[Mapping[str, Any]]:
    """Prevent non-object logs/metrics from being misclassified as Kubernetes resources.

    The legacy resource engine has a text fallback so a metric containing the word
    `container` could look like a Pod. Mark non-object evidence with an unsupported
    synthetic kind while preserving its metric/log fields for feature and timeline analysis.
    """
    result: List[Mapping[str, Any]] = []
    for item in evidence:
        if not isinstance(item, Mapping):
            continue
        resource = _resource(item)
        if resource.get("kind"):
            result.append(item)
            continue
        copied = deepcopy(dict(item))
        copied["kind"] = "NonResourceEvidence"
        result.append(copied)
    return result


def _finding(
    code: str,
    severity: str,
    message: str,
    evidence_id: str,
    resource_kind: str,
    resource_name: Optional[str],
    *,
    handoff: Optional[str] = None,
    details: Optional[Mapping[str, Any]] = None,
) -> Dict[str, Any]:
    return {
        "code": code,
        "severity": severity,
        "message": message,
        "resource_kind": resource_kind,
        "resource_name": resource_name,
        "evidence_ids": [evidence_id],
        "anomaly_start": None,
        "handoff": handoff,
        "details": dict(details or {}),
    }


def _structured_controller_findings(evidence: List[Mapping[str, Any]]) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    for index, item in enumerate(evidence):
        resource = _resource(item)
        kind = _kind(resource)
        if kind not in _CONTROLLER_KINDS:
            continue
        status = _status(resource)
        name = _metadata(resource).get("name")
        eid = _eid(item, index)
        conditions = status.get("conditions")
        if not isinstance(conditions, list):
            continue
        for condition in conditions:
            if not isinstance(condition, Mapping):
                continue
            ctype = str(condition.get("type") or "").lower()
            cstatus = str(condition.get("status") or "").lower()
            reason = str(condition.get("reason") or "")
            reason_lower = reason.lower()
            message = str(condition.get("message") or "")
            message_lower = message.lower()
            if (
                reason_lower == "progressdeadlineexceeded"
                or "progress deadline" in message_lower
                or (ctype == "progressing" and cstatus == "false" and "deadline" in reason_lower)
            ):
                findings.append(_finding(
                    "rollout_stalled",
                    "high",
                    f"{kind} rollout is stalled: {reason or message or 'Progressing=False'}",
                    eid,
                    kind,
                    str(name) if name else None,
                    handoff="change",
                    details={"condition_type": condition.get("type"), "condition_status": condition.get("status"), "reason": reason},
                ))
            if ctype == "replicafailure" and cstatus == "true":
                findings.append(_finding(
                    "replica_failure_condition",
                    "high",
                    f"{kind} reports ReplicaFailure=True",
                    eid,
                    kind,
                    str(name) if name else None,
                    handoff="change",
                    details={"reason": reason, "message": message[:240]},
                ))
    return findings


def _structured_scheduling_findings(evidence: List[Mapping[str, Any]]) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    for index, item in enumerate(evidence):
        if str(item.get("type") or "").lower() not in {"event", "alert", "log"}:
            continue
        text = _event_text(item)
        if not text:
            continue
        eid = _eid(item, index)
        resource = _resource(item)
        involved = resource.get("involvedObject") if isinstance(resource.get("involvedObject"), Mapping) else {}
        name = involved.get("name") or _metadata(resource).get("name")
        if "failedscheduling" in text or "failed scheduling" in text:
            if "insufficient cpu" in text or "insufficient memory" in text:
                findings.append(_finding(
                    "insufficient_resources",
                    "high",
                    "Scheduler reports insufficient CPU or memory",
                    eid,
                    "pod",
                    str(name) if name else None,
                    handoff="infrastructure",
                    details={"insufficient_cpu": "insufficient cpu" in text, "insufficient_memory": "insufficient memory" in text},
                ))
            if any(token in text for token in ("node affinity", "pod affinity", "anti-affinity", "nodeaffinity", "podantiaffinity")):
                findings.append(_finding(
                    "affinity_constraint",
                    "medium",
                    "Affinity or anti-affinity contributes to scheduling failure",
                    eid,
                    "pod",
                    str(name) if name else None,
                ))
            if any(token in text for token in ("untolerated taint", "didn't tolerate", "does not tolerate", "taint")):
                findings.append(_finding(
                    "taint_toleration_mismatch",
                    "medium",
                    "Taint/toleration constraint contributes to scheduling failure",
                    eid,
                    "pod",
                    str(name) if name else None,
                ))
    return findings


def _merge_findings(existing: Iterable[Mapping[str, Any]], extra: Iterable[Mapping[str, Any]]) -> List[Dict[str, Any]]:
    merged: Dict[Tuple[str, str, str], Dict[str, Any]] = {}
    for finding in list(existing) + list(extra):
        if not isinstance(finding, Mapping) or not finding.get("code"):
            continue
        key = (
            str(finding.get("code")),
            str(finding.get("resource_kind") or ""),
            str(finding.get("resource_name") or ""),
        )
        if key not in merged:
            merged[key] = dict(finding)
            continue
        previous = merged[key]
        previous["evidence_ids"] = list(dict.fromkeys(
            [str(value) for value in (previous.get("evidence_ids") or []) + (finding.get("evidence_ids") or []) if value]
        ))
        if not previous.get("handoff") and finding.get("handoff"):
            previous["handoff"] = finding.get("handoff")
        details = dict(previous.get("details") or {})
        details.update(dict(finding.get("details") or {}))
        previous["details"] = details
    return list(merged.values())[:100]


def _attach_findings_to_resources(result: Dict[str, Any], findings: List[Dict[str, Any]]) -> None:
    analyses = result.get("resource_analyses")
    if not isinstance(analyses, list):
        return
    for finding in findings:
        target_kind = str(finding.get("resource_kind") or "")
        target_name = str(finding.get("resource_name") or "")
        for analysis in analyses:
            if not isinstance(analysis, dict):
                continue
            if str(analysis.get("kind") or "") != target_kind:
                continue
            if target_name and str(analysis.get("name") or "") != target_name:
                continue
            rows = analysis.setdefault("findings", [])
            if not any(isinstance(row, Mapping) and row.get("code") == finding.get("code") for row in rows):
                rows.append(dict(finding))
            analysis["health"] = "degraded"
            break


def build_kubernetes_analysis(
    evidence: List[Mapping[str, Any]],
    *,
    service_name: Optional[str] = None,
    context: Optional[Mapping[str, Any]] = None,
) -> Dict[str, Any]:
    safe_for_object_classification = _object_safe_evidence(evidence)
    result = _base_build_kubernetes_analysis(
        safe_for_object_classification,
        service_name=service_name,
        context=context,
    )
    structural = _structured_controller_findings(evidence) + _structured_scheduling_findings(evidence)
    result["findings"] = _merge_findings(result.get("findings") or [], structural)
    _attach_findings_to_resources(result, structural)

    handoffs = [str(value) for value in result.get("handoff_candidates") or [] if value]
    for finding in structural:
        target = finding.get("handoff")
        if target and target not in handoffs:
            handoffs.append(str(target))
    result["handoff_candidates"] = handoffs[:6]

    cause = result.get("kubernetes_vs_infrastructure")
    if not isinstance(cause, dict):
        cause = {}
        result["kubernetes_vs_infrastructure"] = cause
    domains = [str(value) for value in cause.get("underlying_domains") or []]
    structural_codes = {str(row.get("code")) for row in structural}
    if structural_codes & {"rollout_stalled", "replica_failure_condition"} and "kubernetes_workload" not in domains:
        domains.append("kubernetes_workload")
    if structural_codes & {"insufficient_resources"} and "infrastructure" not in domains:
        domains.insert(0, "infrastructure")
    cause["underlying_domains"] = domains
    cause["kubernetes_symptom_present"] = bool(cause.get("kubernetes_symptom_present") or structural_codes & {"rollout_stalled", "replica_failure_condition"})

    analyses = result.get("resource_analyses") if isinstance(result.get("resource_analyses"), list) else []
    result["unhealthy_resource_count"] = sum(
        1 for row in analyses if isinstance(row, Mapping) and row.get("health") in {"degraded", "constrained"}
    )
    result["pipeline_enrichment"] = {
        "structured_rollout_conditions": True,
        "structured_scheduling_constraints": True,
        "non_resource_metric_log_classification_guard": True,
    }
    return result
