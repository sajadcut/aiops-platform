from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Optional

from apps.approval_service.binding import assert_consumed_bound
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

    Executable runbooks accept only a consumed approval context that is bound
    to the exact execution intent and carries the ephemeral single-use claim
    minted for the PostgreSQL consume CAS winner. Plain booleans/IDs are never
    execution authority.
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
        approval_context: Optional[Dict[str, Any]] = None,
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

        if dry_run:
            fingerprint = execution_fingerprint(
                {
                    "tool_name": tool_name,
                    "runbook_id": runbook_id,
                    "action": requested_action,
                    "target": target,
                    "parameters": parameters,
                    "incident_id": None,
                    "approval_id": None,
                    "rollback": bool(rollback_requested),
                }
            )
            return {
                "status": "dry_run",
                "fingerprint": fingerprint,
                "runbook_id": runbook_id,
                "tool_name": tool_name,
                "action": requested_action,
                "target": target,
                "parameters": parameters,
            }

        if approval_context is None:
            # Backward-compatible arguments remain in the signature only to
            # fail closed for old internal callers. A bool/ID pair is not a
            # durable execution capability.
            raise ValueError("runbook_execution_claim_required")

        context_approval_id = str(
            approval_context.get("approval_id") or ""
        ).strip()
        context_incident_id = str(
            approval_context.get("incident_id") or ""
        ).strip()
        if approval_id and str(approval_id) != context_approval_id:
            raise ValueError("approval_id_context_mismatch")
        if incident_id and str(incident_id) != context_incident_id:
            raise ValueError("approval_incident_context_mismatch")

        assert_consumed_bound(
            approval_context,
            incident_id=context_incident_id,
            tool_name=tool_name,
            action=requested_action,
            target=target,
            parameters=parameters,
            timeout=timeout,
            runbook_id=runbook_id,
            runbook_version=str(runbook.get("version") or ""),
            rollback=rollback_requested,
            execution_claim=claim,
        )

        fingerprint = execution_fingerprint(
            {
                "tool_name": tool_name,
                "runbook_id": runbook_id,
                "action": requested_action,
                "target": target,
                "parameters": parameters,
                "incident_id": context_incident_id,
                "approval_id": context_approval_id,
                "rollback": bool(rollback_requested),
            }
        )
        replay_scoped = True
        if fingerprint in self._completed and not rollback_requested:
            previous = self._completed[fingerprint]
            return {
                "status": "idempotent_replay",
                "fingerprint": fingerprint,
                "result": previous.model_dump(mode="json"),
            }

        claim = str(
            approval_context.get("_execution_claim") or ""
        ).strip()

        request = ExecutionRequest(
            tool_name=tool_name,
            action=requested_action,
            target=target,
            parameters=parameters,
            timeout=timeout,
            agent_name="runbook_executor",
            incident_id=context_incident_id,
            approval_granted=True,
            approval_id=context_approval_id,
            runbook_id=runbook_id,
            runbook_version=str(runbook.get("version") or ""),
            rollback=rollback_requested,
        )
        result = await ExecutionService.execute(request)
        if result.success:
            self._completed[fingerprint] = result
        return {"status": "executed", "fingerprint": fingerprint, "result": result.model_dump(mode="json")}
