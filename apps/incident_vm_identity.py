"""Recover an incident VM target by a *live, read-only* MCP identity check.

Historical Agent summaries are not a service/host binding. Missing or
truncated success flags may prevent old evidence from binding, but a matching
authenticated VM service_status response can restore that assurance without
granting any write permission or relaxing the runbook preflight.
"""
from __future__ import annotations

import ipaddress
import re
from typing import Any

from apps.incident_copilot import vm_binding
from apps.context_service.service_identity import ServiceIdentityResolver
from integrations.vm.mcp_client import VMEdgeMCPClient


def normalized_service(value: Any) -> str:
    return str(value or "").strip().lower().removesuffix(".service")


def _safe_target(value: Any) -> str | None:
    raw = str(value or "").strip()
    try:
        parsed = ipaddress.ip_address(raw)
        if parsed.is_unspecified or parsed.is_multicast or parsed.is_loopback:
            return None
        return str(parsed)
    except ValueError:
        return raw if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{1,252}", raw) else None


def incident_vm_context(incident_context: dict | None, checkpoint: dict | None) -> dict:
    """Merge incident context without suppressing contradictory trigger signals."""
    ctx = dict(incident_context or {})
    saved = (checkpoint or {}).get("state") or {}
    current = saved.get("context") or {}
    if not isinstance(current, dict):
        current = {}
    if not isinstance(ctx, dict):
        ctx = {}
    conflicting = []
    for key in ("trigger_signal", "service_identity"):
        if key in ctx and key in current and ctx[key] != current[key]:
            # Not every field changing over time is suspicious; only the
            # actual target/service identity matters.
            lhs = ctx[key] if isinstance(ctx[key], dict) else {}
            rhs = current[key] if isinstance(current[key], dict) else {}
            if key == "trigger_signal":
                a, b = lhs.get("payload") or lhs, rhs.get("payload") or rhs
                if isinstance(a, dict) and isinstance(b, dict):
                    for field in ("target_ip", "host_ip", "service"):
                        if a.get(field) and b.get(field) and str(a[field]).lower() != str(b[field]).lower():
                            conflicting.append(field)
            else:
                blocking_left, _ = ServiceIdentityResolver.split_conflicts(
                    lhs.get("conflicts"))
                blocking_right, _ = ServiceIdentityResolver.split_conflicts(
                    rhs.get("conflicts"))
                # A persisted RAG disagreement with a verified live name is
                # still useful evidence, but it is NOT a new identity.
                lhs_name = normalized_service(lhs.get("service"))
                rhs_name = normalized_service(rhs.get("service"))
                if (blocking_left or blocking_right or
                    (lhs_name and rhs_name and lhs_name != rhs_name)):
                    conflicting.append("service_identity")
    ctx.update(current)
    if conflicting:
        ctx["_vm_identity_context_conflicts"] = conflicting
    return ctx


def _trusted_signal(service: str, context: dict) -> tuple[set[str], list[str]]:
    targets: set[str] = set()
    refs: list[str] = []
    for field in ("trigger_signal", "incident"):
        outer = context.get(field)
        if not isinstance(outer, dict):
            continue
        payload = outer.get("payload") or outer
        if not isinstance(payload, dict):
            continue
        kind = str(outer.get("source") or outer.get("provider") or "").lower()
        platform = str(payload.get("platform") or payload.get("asset_type") or "").lower()
        # Only bound incident ingest records (Zabbix VM) can provide a
        # *candidate* host. Never follow a host in the user's chat text.
        if kind not in {"zabbix", "zabbix_webhook"} and platform not in {"vm", "linux_vm"}:
            continue
        named = normalized_service(payload.get("service"))
        if named != service:
            continue
        candidate = _safe_target(payload.get("target_ip") or payload.get("host_ip"))
        if candidate:
            targets.add(candidate)
            refs.append("incident_trigger:" + field)
    return targets, refs


def vm_binding_diagnostic(service: str, evidence: list[dict],
                          context: dict | None = None) -> dict:
    """Coded reason for binding failure, usable in audit and dashboard."""
    ctx = context or {}
    if ctx.get("_vm_identity_context_conflicts"):
        return {"reason": "incident_identity_context_conflict", "candidate": None}
    identity = ctx.get("service_identity") or {}
    if isinstance(identity, dict):
        blocking, advisory = ServiceIdentityResolver.split_conflicts(
            identity.get("conflicts"))
        if blocking:
            return {"reason": "service_identity_conflict", "candidate": None,
                    "blocking_kinds": [str(x.get("kind") or "unknown")[:50]
                                       for x in blocking[:5]]}
    else:
        advisory = []
    checked_service = ServiceIdentityResolver.runtime_name_from_verified_mapping(
        service, ctx, evidence)
    name = normalized_service(checked_service)
    if not name or name == "unknown":
        return {"reason": "service_identity_missing", "candidate": None}
    for field in ("trigger_signal", "incident"):
        outer = ctx.get(field)
        if isinstance(outer, dict):
            payload = outer.get("payload") or outer
            if isinstance(payload, dict):
                reported = normalized_service(payload.get("service"))
                if (reported and reported != name
                        and not ServiceIdentityResolver.verified_runtime_alias_matches(
                            reported, name, ctx, evidence)):
                    return {"reason": "incident_service_conflict", "candidate": None}
    vm_targets: set[str] = set()
    refs: list[str] = []
    supported = {"service_status", "process_status", "config_validate",
                 "service_runtime_discovery", "dotnet_config_syntax",
                 "nginx_config_review", "nginx_config_inspect"}
    for row in evidence:
        if not isinstance(row, dict) or row.get("source") != "vm_mcp":
            continue
        raw = row.get("raw_data")
        if not isinstance(raw, dict):
            continue
        if str(raw.get("diagnostic") or "") not in supported:
            continue
        if normalized_service(raw.get("service")) != name:
            continue
        observed_unit = normalized_service(raw.get("unit_id"))
        if observed_unit and observed_unit != name:
            continue
        target = _safe_target(raw.get("target"))
        if not target:
            continue
        # VM-edge emitted an actual status result; no LLM/user supplied
        # target is considered. Check again live before binding.
        if raw.get("success") is False and not any(
            key in raw for key in ("active_state", "running", "valid", "runtime")
        ):
            continue
        vm_targets.add(target)
        if row.get("reference"):
            refs.append(str(row["reference"])[:160])
    signal_targets, signal_refs = _trusted_signal(name, ctx)
    if len(vm_targets) > 1 or len(signal_targets) > 1:
        return {"reason": "conflicting_vm_targets", "candidate": None}
    if vm_targets and signal_targets and vm_targets != signal_targets:
        return {"reason": "alert_vm_target_conflict", "candidate": None}
    targets = vm_targets or signal_targets
    if not targets:
        return {"reason": "verified_target_not_in_incident_evidence", "candidate": None}
    return {
        "reason": "live_service_identity_check_required",
        "candidate": next(iter(targets)),
        "evidence_refs": list(dict.fromkeys(refs + signal_refs))[:8],
        "advisory_knowledge_conflict_count": len(advisory),
    }


async def resolve_vm_binding(
    service: str, evidence: list[dict], context: dict | None,
    *, connector: Any = None, force_live: bool = False,
) -> tuple[dict | None, dict]:
    """Recheck the **candidate**, not a chat-supplied host; status may be failed.

    Result: (binding, diagnostic). Passing here is NOT Approval, and cannot
    bypass a supported validator, runbook action, or permission.
    """
    ctx = context or {}
    bound = vm_binding(service, evidence, ctx) if not ctx.get("_vm_identity_context_conflicts") else None
    diagnosis = vm_binding_diagnostic(service, evidence, ctx)
    if bound is not None and not force_live and diagnosis["reason"] not in {
        "conflicting_vm_targets", "alert_vm_target_conflict",
        "service_identity_conflict", "incident_identity_context_conflict",
        "incident_service_conflict",
    }:
        return bound, {"status": "verified_from_saved_vm_evidence",
                       "verification": bound.get("verification"),
                       "evidence_refs": bound["evidence_refs"],
                       "advisory_knowledge_conflict_count": diagnosis.get(
                           "advisory_knowledge_conflict_count", 0)}
    if diagnosis.get("candidate") is None:
        return None, {"status": diagnosis["reason"], "evidence_refs": []}
    target = diagnosis["candidate"]
    runtime_service = ServiceIdentityResolver.runtime_name_from_verified_mapping(
        service, ctx, evidence)
    name = normalized_service(runtime_service)
    try:
        client = connector or VMEdgeMCPClient()
        fresh = await client.service_status(target, runtime_service)
    except Exception as exc:
        return None, {"status": "vm_mcp_live_identity_check_failed",
                      "error_type": type(exc).__name__, "evidence_refs": diagnosis.get("evidence_refs", [])}
    if not isinstance(fresh, dict) or fresh.get("success") is not True:
        return None, {"status": "vm_mcp_service_status_unavailable",
                      "evidence_refs": diagnosis.get("evidence_refs", [])}
    returned_target = _safe_target(fresh.get("target"))
    returned_service = normalized_service(fresh.get("service"))
    status = str(fresh.get("active_state") or "").strip().lower()
    actual_unit = normalized_service(fresh.get("unit_id"))
    if (returned_target != target or returned_service != name
        or (actual_unit and actual_unit != name)
        or status not in {"active", "failed", "inactive", "activating", "deactivating", "reloading"}
        or str(fresh.get("load_state") or "loaded").lower() not in {"loaded", ""}):
        return None, {"status": "vm_mcp_live_identity_mismatch",
                      "evidence_refs": diagnosis.get("evidence_refs", [])}
    return {
        "target": target, "service": name,
        "evidence_refs": diagnosis.get("evidence_refs", []),
        "verification": "live_service_status",
        "active_state": status, "read_only_verified": True,
    }, {
        "status": "verified_from_live_vm_mcp",
        "service_state": status,
        "advisory_knowledge_conflict_count": diagnosis.get(
            "advisory_knowledge_conflict_count", 0),
        "evidence_refs": diagnosis.get("evidence_refs", []),
        "live_observation": {
            "success": True, "target": target, "service": name,
            "active_state": status,
            "sub_state": str(fresh.get("sub_state") or "")[:60],
            "result": str(fresh.get("result") or "")[:60],
        },
    }


def vm_status_answer(observation: dict, *, persian: bool = True) -> str:
    """Only live service_status fields form a current-state assertion."""
    if observation.get("success") is not True:
        return "استعلام زندهٔ وضعیت سرویس موفق نبود." if persian else "Live VM status read failed."
    service = str(observation.get("service") or "unknown")[:80]
    active = str(observation.get("active_state") or "unknown")[:40]
    sub = str(observation.get("sub_state") or "unknown")[:40]
    result = str(observation.get("result") or "unknown")[:50]
    target = str(observation.get("target") or "unknown")[:120]
    if persian:
        return (f"نتیجهٔ زندهٔ VM MCP برای سرویس {service} روی میزبان {target}: "
                f"ActiveState={active}، SubState={sub}، Result={result}. "
                "این مشاهده فقط وضعیت فعلی را نشان می‌دهد؛ اجرای Start/Restart "
                "نیازمند بررسی پیش‌شرط‌ها و تأیید جداگانه است.")
    return (f"Live VM MCP status for {service} on {target}: "
            f"ActiveState={active}, SubState={sub}, Result={result}. "
            "This observation does not grant permission to start or restart the service.")
