"""Evidence-grounded recovery *advice*, independent of executable authorization.

Operators should see a conditional start/restart proposal even if an evaluator
cannot yet authorize an execution plan. This module never creates an execution
request, approval or tool call. The strict execution gates remain unchanged.
"""
from __future__ import annotations

from typing import Any, Iterable, Mapping


_UNHEALTHY = {"failed": "restart_service", "inactive": "start_service"}
_HEALTHY = {"active", "running", "up"}
_ALLOWED_SOURCES = {"zabbix", "prometheus", "elasticsearch", "kubernetes"}


def _service(value: Any) -> str:
    value = str(value or "").strip().lower()
    return value[:-8] if value.endswith(".service") else value


def _reference(item: Mapping[str, Any]) -> str:
    return str(item.get("reference") or item.get("id") or item.get("evidence_id") or "")[:160]


def _matching_vm_evidence(
    evidence: Iterable[Mapping[str, Any]], service: str, diagnostic: str,
    target: str | None = None,
) -> list[tuple[Mapping[str, Any], Mapping[str, Any]]]:
    rows = []
    for item in evidence:
        if not isinstance(item, Mapping) or item.get("source") != "vm_mcp":
            continue
        raw = item.get("raw_data")
        if not isinstance(raw, Mapping) or raw.get("diagnostic") != diagnostic:
            continue
        if raw.get("success") is not True or _service(raw.get("service") or raw.get("process")) != service:
            continue
        address = str(raw.get("target") or "").strip()
        if not address or (target is not None and address != target):
            continue
        rows.append((item, raw))
    return rows


def build_vm_recovery_advisory(
    *, evidence: Iterable[Mapping[str, Any]], service_name: str | None,
    context: Mapping[str, Any] | None = None,
) -> dict[str, Any] | None:
    """Return a non-executable, auditable service advisory or None.

    Fail closed on target ambiguity, contradictory live service state, explicit
    signal/service conflicts, recovered state or a known-invalid configuration.
    A missing validator blocks *execution*, not the operator-facing proposal.
    """
    service = _service(service_name)
    if not service or service in {"unknown", "unidentified"}:
        return None
    ctx = context if isinstance(context, Mapping) else {}
    identity = ctx.get("service_identity")
    if isinstance(identity, Mapping) and identity.get("conflicts"):
        return None
    trigger = ctx.get("trigger_signal")
    if isinstance(trigger, Mapping):
        source = str(trigger.get("source") or "").strip().lower()
        if source and source not in _ALLOWED_SOURCES:
            return None
        payload = trigger.get("payload")
        if not isinstance(payload, Mapping):
            payload = trigger
        # Do not attach a service restart to another service's alert.
        named = _service(payload.get("service"))
        if named and named != service:
            return None

    rows = list(evidence)
    statuses = _matching_vm_evidence(rows, service, "service_status")
    if not statuses:
        return None
    targets = {str(raw["target"]).strip() for _, raw in statuses}
    if len(targets) != 1:
        return None
    target = next(iter(targets))
    if isinstance(trigger, Mapping):
        payload = trigger.get("payload")
        if not isinstance(payload, Mapping):
            payload = trigger
        expected_target = str(payload.get("target_ip") or payload.get("host_ip") or "").strip()
        if expected_target and expected_target != target:
            # No cross-host recovery suggestion even when service names match.
            return None
    # A recovered or ambiguous status must not become a stale recovery
    # recommendation. Conflicting snapshots are shown as gaps elsewhere.
    states = {str(raw.get("active_state") or raw.get("status") or "").strip().lower()
              for _, raw in statuses}
    if len(states) != 1 or next(iter(states)) not in _UNHEALTHY:
        return None
    state = next(iter(states))
    status_item, status_raw = statuses[-1]
    action = _UNHEALTHY[state]
    refs = [_reference(status_item)]
    checks: list[str] = []

    processes = _matching_vm_evidence(rows, service, "process_status", target)
    if processes and any(raw.get("running") is True for _, raw in processes):
        return None
    if processes:
        refs.extend(_reference(item) for item, _ in processes)
    else:
        checks.append("Recheck service process presence and service status using read-only VM MCP.")

    config = _matching_vm_evidence(rows, service, "config_validate", target)
    if config:
        refs.extend(_reference(item) for item, _ in config)
    config_invalid = any(raw.get("supported") is True and raw.get("valid") is False for _, raw in config)
    config_verified = bool(config) and all(
        raw.get("supported") is True and raw.get("valid") is True
        and raw.get("success") is True for _, raw in config
    )
    if config_invalid:
        # A known-bad configuration requires a separate repair proposal first.
        # Returning the diagnostic (rather than restart) avoids suggesting an
        # operation known to fail.
        action = None
        disposition = "repair_configuration_first"
        checks.append("Correct the observed invalid configuration and re-run its real validator.")
    elif not config_verified:
        disposition = "conditional_recovery"
        checks.append(
            "Configuration validation is unavailable or inconclusive; obtain a "
            "service-specific, approved safety precheck before execution."
        )
    else:
        disposition = "conditional_recovery"

    result = str(status_raw.get("result") or "")[:100].lower()
    if result == "timeout":
        checks.append(
            "Inspect systemd journal, TimeoutStartSec, ExecStart/ExecStartPre, "
            "application startup, dependent services and recent changes."
        )
    else:
        checks.append("Inspect recent service journal, exit status, dependencies and change/audit history.")
    checks.extend([
        "Before any write, recheck target, service state, process, configuration and change policy.",
        "After an approved recovery, verify service health, expected listeners and the original alert.",
    ])
    return {
        "status": disposition,
        "service": service, "target": target, "observed_state": state,
        "systemd_result": result or "unknown", "suggested_action": action,
        "risk_level": "high", "configuration_validation": (
            "INVALID" if config_invalid else "VALID" if config_verified else "UNVERIFIED"
        ),
        "reason": (
            "systemd reported a failed service after timeout; the cause is not yet proven"
            if state == "failed" and result == "timeout"
            else "systemd reported the service as " + state + "; the cause is not yet proven"
        ),
        "prerequisite_checks": checks[:6],
        "operator_question": (
            "Review the evidence and authorize the necessary read-only investigation; "
            "after service-specific safety checks, consider a separate approval-bound "
            + ("restart" if action == "restart_service" else "start")
            + " proposal."
        ) if action else "Review and authorize a configuration repair proposal before service recovery.",
        "evidence_refs": list(dict.fromkeys(ref for ref in refs if ref))[:8],
        "requires_human_review": True,
        "approval_status": "not_requested",
        "execution_authority": False,
        "authorizes_execution": False,
        "counts_as_live_evidence": False,
    }
