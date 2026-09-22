from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Optional

from apps.execution_service import ExecutionRequest, ExecutionResult, ExecutionService
from apps.execution_service.idempotency import execution_fingerprint
from apps.runbook_service.registry import RunbookRegistry


@dataclass(frozen=True)
class RunbookExecution:
    runbook_id: str
    fingerprint: str
    dry_run: bool
    rollback_requested: bool = False


class RunbookExecutor:
    """Safe runtime boundary for registered runbooks.

    Approval-required tools accept only approval context that an upstream durable
    approval path has validated, bound to the requested operation, and consumed.
    Plain approval identifiers are not propagated unless approval_granted is true.
    """

    def __init__(self, registry: RunbookRegistry):
        self.registry = registry
        self._completed: Dict[str, ExecutionResult] = {}

    def validate(self, runbook_id: str, parameters: Dict[str, Any]) -> Dict[str, Any]:
        runbook = self.registry.get(runbook_id)
        if not runbook:
            raise ValueError("runbook_not_found")
        return self.registry.validate(runbook_id, parameters)

    async def execute(
        self,
        runbook_id: str,
        *,
        tool_name: str,
        target: str,
        parameters: Dict[str, Any],
        action: Optional[str] = None,
        timeout: int = 30,
        dry_run: bool = False,
        incident_id: Optional[str] = None,
        approval_id: Optional[str] = None,
        approval_granted: bool = False,
        rollback_requested: bool = False,
    ) -> Dict[str, Any]:
        runbook = self.registry.get(runbook_id)
        if not runbook:
            raise ValueError("runbook_not_found")
        self.registry.validate(runbook_id, parameters)

        execution_contract = (
            dict(runbook.get("execution") or {})
            if isinstance(runbook.get("execution"), dict)
            else {}
        )
        requested_action = str(
            action
            or ("rollback" if rollback_requested else runbook.get("action") or runbook_id)
        )
        if not execution_contract and not dry_run:
            raise ValueError("runbook_not_executable")
        if execution_contract:
            contract_tool = str(execution_contract.get("tool") or "").strip()
            allowed_actions = {
                str(value).strip()
                for value in execution_contract.get("allowed_actions", [])
                if str(value).strip()
            }
            if not contract_tool:
                raise ValueError("runbook_execution_tool_missing")
            if tool_name != contract_tool:
                raise ValueError("runbook_tool_mismatch")
            if rollback_requested:
                rollback_actions = {
                    str(step.get("action") or "").strip()
                    for step in runbook.get("rollback", [])
                    if isinstance(step, dict)
                    and str(step.get("action") or "").strip() not in {"", "none"}
                }
                if requested_action not in rollback_actions:
                    raise ValueError("runbook_rollback_not_allowed")
            elif requested_action not in allowed_actions:
                raise ValueError("runbook_action_not_allowed")

        fingerprint = execution_fingerprint(
            {
                "tool_name": tool_name,
                "runbook_id": runbook_id,
                "action": requested_action,
                "target": target,
                "parameters": parameters,
                "incident_id": incident_id,
                "approval_id": approval_id if approval_granted else None,
                "rollback": bool(rollback_requested),
            }
        )
        replay_scoped = bool(approval_granted and approval_id)
        if replay_scoped and fingerprint in self._completed and not rollback_requested:
            previous = self._completed[fingerprint]
            return {
                "status": "idempotent_replay",
                "fingerprint": fingerprint,
                "result": previous.model_dump(mode="json"),
            }

        if dry_run:
            return {
                "status": "dry_run", "fingerprint": fingerprint, "runbook_id": runbook_id,
                "tool_name": tool_name, "action": requested_action,
                "target": target, "parameters": parameters,
            }

        authorized_approval_id = approval_id if approval_granted else None
        authorized_incident_id = incident_id if approval_granted else None
        request = ExecutionRequest(
            tool_name=tool_name, action=requested_action, target=target, parameters=parameters, timeout=timeout,
            agent_name="runbook_executor", incident_id=authorized_incident_id,
            approval_granted=bool(approval_granted), approval_id=authorized_approval_id,
            runbook_id=runbook_id, runbook_version=str(runbook.get("version") or ""), rollback=rollback_requested,
        )
        result = await ExecutionService.execute(request)
        if result.success and replay_scoped:
            self._completed[fingerprint] = result
        return {"status": "executed", "fingerprint": fingerprint, "result": result.model_dump(mode="json")}
