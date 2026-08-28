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

    Approval booleans are compatibility metadata only. Approval-required tools
    must carry a signed execution capability issued after durable approval
    validation and consume.
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
        timeout: int = 30,
        dry_run: bool = False,
        incident_id: Optional[str] = None,
        approval_id: Optional[str] = None,
        approval_granted: bool = False,
        execution_capability: Optional[str] = None,
        rollback_requested: bool = False,
    ) -> Dict[str, Any]:
        runbook = self.registry.get(runbook_id)
        if not runbook:
            raise ValueError("runbook_not_found")
        self.registry.validate(runbook_id, parameters)

        fingerprint = execution_fingerprint(tool_name, runbook_id, target, parameters)
        if fingerprint in self._completed and not rollback_requested:
            previous = self._completed[fingerprint]
            return {"status": "idempotent_replay", "fingerprint": fingerprint, "result": previous.model_dump(mode="json")}

        if dry_run:
            return {
                "status": "dry_run", "fingerprint": fingerprint, "runbook_id": runbook_id,
                "tool_name": tool_name, "target": target, "parameters": parameters,
            }

        action = "rollback" if rollback_requested else runbook.get("action", runbook_id)
        request = ExecutionRequest(
            tool_name=tool_name, action=action, target=target, parameters=parameters, timeout=timeout,
            agent_name="runbook_executor", incident_id=incident_id, approval_granted=bool(approval_granted),
            approval_id=approval_id, execution_capability=execution_capability,
            runbook_id=runbook_id, runbook_version=str(runbook.get("version") or ""), rollback=rollback_requested,
        )
        result = await ExecutionService.execute(request)
        if result.success:
            self._completed[fingerprint] = result
        return {"status": "executed", "fingerprint": fingerprint, "result": result.model_dump(mode="json")}
