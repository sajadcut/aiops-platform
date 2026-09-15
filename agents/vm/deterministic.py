from __future__ import annotations

from typing import Any, Dict, Iterable, Optional


def _evidence_ref(item: Dict[str, Any]) -> str:
    return str(
        item.get("evidence_id")
        or item.get("id")
        or item.get("reference")
        or item.get("source_id")
        or ""
    ).strip()


def classify_vm_service_fault(
    evidence: Iterable[Dict[str, Any]],
    service: Optional[str],
) -> Optional[Dict[str, Any]]:
    """Classify high-signal VM service faults from normalized live evidence.

    This classifier is deliberately narrow and deterministic. It never executes
    a command and never turns agent prose into an action. Its purpose is to keep
    obvious operational facts usable even when an LLM specialist is unavailable
    or returns malformed/truncated output.
    """
    service_name = str(service or "").strip()
    if not service_name:
        return None

    diagnostics: Dict[str, Dict[str, Any]] = {}
    references: Dict[str, str] = {}
    for item in evidence:
        if not isinstance(item, dict):
            continue
        raw = item.get("raw_data")
        if not isinstance(raw, dict):
            continue
        diagnostic = str(raw.get("diagnostic") or "").strip().lower()
        if diagnostic not in {
            "service_status",
            "process_status",
            "config_validate",
            "port_listener_status",
            "tcp_check",
        }:
            continue
        evidence_service = str(raw.get("service") or raw.get("process") or "").strip()
        if evidence_service and diagnostic in {"service_status", "process_status", "config_validate"}:
            if evidence_service != service_name:
                continue
        diagnostics[diagnostic] = raw
        ref = _evidence_ref(item)
        if ref:
            references[diagnostic] = ref

    service_status = diagnostics.get("service_status") or {}
    process_status = diagnostics.get("process_status") or {}
    config_status = diagnostics.get("config_validate") or {}
    listener_status = diagnostics.get("port_listener_status") or {}
    tcp_status = diagnostics.get("tcp_check") or {}

    active_state = str(service_status.get("active_state") or service_status.get("status") or "").lower()
    sub_state = str(service_status.get("sub_state") or "").lower()
    service_stopped = active_state in {"inactive", "failed"} or sub_state in {"dead", "failed"}
    process_absent = process_status.get("running") is False
    config_supported = config_status.get("supported") is True
    config_valid = config_status.get("valid") is True
    listener_down = listener_status.get("supported") is not False and listener_status.get("listening") is False
    tcp_down = tcp_status.get("supported") is not False and tcp_status.get("reachable") is False
    symptom_down = listener_down or tcp_down

    if not (service_stopped and process_absent and config_supported and config_valid):
        return None

    used = [
        references[key]
        for key in ("service_status", "process_status", "config_validate", "port_listener_status", "tcp_check")
        if references.get(key)
    ]
    confidence = 0.98 if symptom_down else 0.94
    findings = [
        f"{service_name} service is {active_state or 'inactive'} with sub-state {sub_state or 'unknown'}",
        f"{service_name} process is not running",
        f"{service_name} configuration validation succeeded",
    ]
    if listener_down:
        findings.append("expected local TCP listener is absent")
    if tcp_down:
        findings.append("TCP symptom remains unreachable")

    return {
        "fault_code": "service_stopped",
        "confidence": confidence,
        "severity": "high" if symptom_down else "medium",
        "health_status": "unhealthy",
        "findings": findings,
        "evidence_ids": used,
        "hypothesis": {
            "hypothesis": f"{service_name} service is stopped",
            "probability": confidence,
            "evidence_ids": used,
            "conflicting_evidence_ids": [],
            "falsification_checks": [
                f"After an approved start, confirm {service_name} is active and the original symptom has recovered"
            ],
            "impacted_components": [service_name],
            "recommended_next_evidence": [f"{service_name} service logs around the stop event"],
        },
        "remediation_candidate": f"Start {service_name} service",
        "suggested_action": "start_service",
    }
