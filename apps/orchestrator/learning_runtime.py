from __future__ import annotations

from typing import Any, Dict

from apps.audit_service import AuditService
from apps.orchestrator.learning_signal_aware import LearningSignalAwareE2EOrchestrator
from apps.orchestrator.runtime import DurableWorkflowRuntime


class LearningDurableWorkflowRuntime(DurableWorkflowRuntime):
    """Durable workflow runtime with Operational Memory v2 outcome learning."""

    def __init__(self, session):
        super().__init__(
            session,
            orchestrator_cls=LearningSignalAwareE2EOrchestrator,
        )

    async def resume_after_approval(self, incident_id: str) -> Dict[str, Any]:
        checkpoint = await self.checkpoints.load(incident_id)
        if not checkpoint:
            raise ValueError("workflow_checkpoint_not_found")
        if checkpoint.get("status") == "completed":
            raise ValueError("workflow_already_completed")

        state = checkpoint["state"]
        approval = state.get("approval") or {}
        approval_id = approval.get("approval_id")
        if not approval_id:
            raise ValueError("approval_not_found_in_checkpoint")
        durable = await self.approvals.get(str(approval_id))
        if not durable or durable.get("status") != "approved":
            raise ValueError("approval_not_granted")

        execution_request = dict(state.get("execution_request") or {})
        if not execution_request:
            raise ValueError("execution_request_not_found_in_checkpoint")
        self._assert_binding(durable, execution_request)

        consumed = await self.approvals.consume(str(approval_id))
        if not consumed or consumed.get("status") != "consumed":
            raise ValueError("approval_already_consumed")
        AuditService.record(
            "approval_consumed",
            "durable_runtime",
            incident_id,
            execution_request.get("action"),
            "recorded",
            {
                "approval_id": str(approval_id),
                "tool_name": execution_request.get("tool_name"),
                "target": execution_request.get("target"),
            },
        )

        state["approval"] = consumed
        execution_request["approval_granted"] = True
        execution_request["approval_id"] = str(approval_id)
        execution_request["incident_id"] = incident_id
        state["execution_request"] = execution_request
        state["current_node"] = "execution"

        orchestrator = self._orchestrator_type()(db=self.session)
        execution_tokens = self._bind_execution_context(execution_request)
        try:
            result = await orchestrator._execution_node(state)
        finally:
            self._reset_execution_context(execution_tokens)

        execution_result = result.get("execution_result") or {}
        if not execution_result.get("success"):
            result["terminal_reason"] = (
                execution_result.get("reason") or "execution_failed"
            )
            result = await orchestrator._memory_node(result)
            await self.checkpoints.mark_failed(incident_id, result)
            await self._set_incident_status(incident_id, "escalated")
            await self._flush_audit(incident_id)
            await self.incidents.commit()
            return result

        verification_tokens = self._bind_execution_context(execution_request)
        try:
            result = await orchestrator._verification_node(result)
        finally:
            self._reset_execution_context(verification_tokens)

        verification = result.get("verification_result") or {}
        verification_status = str(
            verification.get("status") or "inconclusive"
        ).lower()
        if verification_status != "success":
            result["terminal_reason"] = f"verification_{verification_status}"

        result = await orchestrator._memory_node(result)
        result = await orchestrator._end_node(result)
        if verification_status == "success":
            await self.checkpoints.mark_completed(incident_id, result)
            await self._set_incident_status(incident_id, "resolved")
        else:
            await self.checkpoints.mark_failed(incident_id, result)
            await self._set_incident_status(incident_id, "escalated")

        await self.incidents.add_findings(
            incident_id,
            result.get("findings", []),
        )
        final_fields = self._incident_fields(result)
        await self.incidents.upsert_incident(
            incident_id=incident_id,
            source=final_fields["source"],
            service=final_fields["service"],
            severity=final_fields["severity"],
            summary=final_fields["summary"],
            status=(
                "resolved"
                if verification_status == "success"
                else "escalated"
            ),
            context=final_fields["context"],
        )
        await self._flush_audit(incident_id)
        await self.incidents.commit()
        return result
