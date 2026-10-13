from __future__ import annotations

from typing import Any, Dict, Iterable, Optional

from integrations.vm.service_adapters import enrich_legacy_config_diagnostic


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
        diagnostics[diagnostic] = (
            enrich_legacy_config_diagnostic(raw)
            if diagnostic == "config_validate" and item.get("source") == "vm_mcp"
            else raw
        )
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

    # A failed compiler-style syntax check is actionable diagnosis even though
    # it is NOT proof of why somebody stopped the service. It must NEVER
    # authorize start/restart until the actual config is fixed and rechecked.
    if (service_stopped and config_supported
            and config_status.get("success") is True
            and config_status.get("valid") is False):
        path = str(config_status.get("config_file") or "نامشخص")[:300]
        line = config_status.get("error_line")
        line_number = line if isinstance(line, int) and 0 < line < 1000000 else None
        syntax_message = str(config_status.get("syntax_error") or config_status.get("detail") or "configuration syntax check failed")[:450]
        used = [
            references[key] for key in ("service_status", "config_validate", "process_status")
            if references.get(key)
        ]
        where = f"{path}:{line_number}" if line_number else path
        return {
            "fault_code": "service_configuration_invalid",
            "stop_attribution": "unknown",
            "requires_operator_review": True,
            "confidence": 0.95,
            "severity": "high",
            "health_status": "unhealthy",
            "config_file": path, "error_line": line_number,
            "syntax_error": syntax_message,
            "findings": [
                f"{service_name} is stopped; config test failed in {where}",
                f"Reported syntax error: {syntax_message}",
                "This configuration failure may prevent starting the service; the original stop cause remains unknown",
                "Do NOT start before correcting and successfully revalidating the configuration",
            ],
            "evidence_ids": used,
            "hypothesis": {
                "hypothesis": f"{service_name} cannot be safely started with the current invalid configuration",
                "probability": 0.95, "evidence_ids": used,
                "conflicting_evidence_ids": [],
                "falsification_checks": [
                    "After authorized configuration repair, run the fixed syntax validator again",
                    "Only if valid, consider an operator-approved start and verify health",
                ],
                "impacted_components": [service_name],
                "recommended_next_evidence": [f"Re-run config_validate for {service_name} after an authorized fix"],
            },
            "remediation_candidate": (
                f"Correct {service_name} configuration at {where}, re-run validation; "
                "if valid, propose start_service for separate operator approval"
            ),
            "suggested_action": None,
        }

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
        "Stop cause and actor are unverified; manual, automated or maintenance stop remains possible",
    ]
    if listener_down:
        findings.append("expected local TCP listener is absent")
    if tcp_down:
        findings.append("TCP symptom remains unreachable")

    return {
        "fault_code": "service_stopped",
        "stop_attribution": "unknown",
        "requires_operator_review": True,
        "confidence": confidence,
        # Operational severity is intentionally kept separate from write risk.
        # The start action is still high-risk/governed, while this confirmed
        # classification can proceed to the Decision/Approval layer.
        "severity": "medium",
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
        "remediation_candidate": f"Propose starting {service_name} after operator approval; investigate stop origin separately",
        "suggested_action": "start_service",
    }
