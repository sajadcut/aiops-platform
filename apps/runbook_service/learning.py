from __future__ import annotations

from typing import Any, Dict, Optional

from apps.memory_service import OperationalMemoryService
from apps.memory_service.builder import OperationalMemoryBuilder


def build_runbook_memory_state(
    *,
    incident_id: str,
    runbook: Dict[str, Any],
    tool_name: str,
    action: str,
    target: str,
    parameters: Dict[str, Any],
    approval: Dict[str, Any],
    execution_result: Dict[str, Any],
    verification_result: Dict[str, Any],
    before_snapshot: Optional[Dict[str, Any]] = None,
    after_snapshot: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Build the canonical Memory-builder state for direct runbook execution."""
    service = str(parameters.get("service") or target or "unknown")
    evidence = []
    for snapshot in (before_snapshot or {}, after_snapshot or {}):
        for item in snapshot.get("evidence") or []:
            if isinstance(item, dict):
                evidence.append(item)

    runbook_id = str(runbook.get("id") or runbook.get("name") or "")
    version = str(runbook.get("version") or "")
    risk = str(runbook.get("risk") or "unknown")
    summary = f"Governed runbook {runbook_id} {action} on {target}"

    return {
        "incident_id": incident_id,
        "service_name": service,
        "evidence_summary": summary,
        "context": {
            "incident": {
                "source": "runbook",
                "service": service,
                "severity": risk,
                "summary": summary,
            },
            "trigger_signal": {
                "source": "runbook",
                "signal_type": "governed_runbook_execution",
                "summary": summary,
            },
            "evidence": evidence,
        },
        "findings": [],
        "coordination": {},
        "final_plan": (
            f"Execute registered runbook {runbook_id} action {action} through "
            f"{tool_name} and verify registered post-action objectives."
        ),
        "execution_request": {
            "tool_name": tool_name,
            "action": action,
            "target": target,
            "parameters": dict(parameters or {}),
            "incident_id": incident_id,
            "approval_id": approval.get("approval_id"),
            "approval_granted": approval.get("status") == "consumed",
            "runbook_id": runbook_id,
            "runbook_version": version,
            "rollback": False,
        },
        "execution_result": dict(execution_result or {}),
        "verification_result": dict(verification_result or {}),
        "approval": dict(approval or {}),
    }


async def record_runbook_outcome(
    db,
    **kwargs: Any,
) -> Optional[str]:
    state = build_runbook_memory_state(**kwargs)
    episode = OperationalMemoryBuilder.build(state)
    evidence_count = int(
        (episode.get("evidence_provenance") or {}).get("evidence_count") or 0
    )
    verification = dict(kwargs.get("verification_result") or {})
    verification_status = str(
        verification.get("status") or "inconclusive"
    ).strip().lower()
    execution_success = bool((kwargs.get("execution_result") or {}).get("success"))

    # Successful/verified reusable lessons require evidence provenance.
    # Failed or blocked governed attempts are still durable negative experience:
    # otherwise the system can repeat an action that failed before post-action
    # evidence was obtainable.
    negative_outcome = (
        not execution_success
        or verification_status in {
            "failed",
            "failure",
            "blocked",
            "inconclusive",
            "partial",
        }
    )
    if evidence_count <= 0 and not negative_outcome:
        return None
    return str(await OperationalMemoryService(db).add_episode(episode))
