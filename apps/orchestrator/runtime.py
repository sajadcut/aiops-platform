from __future__ import annotations

from typing import Any, Dict

from apps.audit_service import AuditService
from apps.audit_service.postgres import PostgreSQLAuditStore
from apps.incident_service.repository import IncidentRepository
from apps.orchestrator.e2e_graph import E2EOrchestrator
from apps.orchestrator.workflow_store import WorkflowCheckpointStore
from apps.approval_service.postgres import PostgreSQLApprovalStore


class DurableWorkflowRuntime:
    """PostgreSQL-backed runtime around the governed LangGraph workflow."""

    def __init__(self, session):
        self.session = session
        self.checkpoints = WorkflowCheckpointStore(session)
        self.incidents = IncidentRepository(session)
        self.approvals = PostgreSQLApprovalStore(session)
        self.audit = PostgreSQLAuditStore(session)

    async def _flush_audit(self, incident_id: str) -> None:
        await AuditService.flush_to_store(self.audit, incident_id=incident_id)

    async def start(self, state: Dict[str, Any]) -> Dict[str, Any]:
        incident_id = str(state["incident_id"])
        await self.incidents.upsert_incident(
            incident_id=incident_id,
            source=str(state.get("context", {}).get("incident", {}).get("source") or "api"),
            service=str(state.get("service_name") or "unknown"),
            severity=state.get("context", {}).get("incident", {}).get("severity"),
            summary=state.get("context", {}).get("incident", {}).get("summary") or state.get("evidence_summary"),
        )
        await self.incidents.add_evidence(incident_id, state.get("live_evidence", {}).get("evidence", []))
        await self.incidents.commit()

        result = await E2EOrchestrator(db=self.session).run(state)
        await self.incidents.add_findings(incident_id, result.get("findings", []))
        await self.incidents.add_evidence(incident_id, result.get("live_evidence", {}).get("evidence", []))

        approval = result.get("approval") or {}
        execution_request = dict(result.get("execution_request") or {})
        if approval.get("approval_id"):
            metadata = dict(approval.get("metadata") or {})
            if execution_request.get("target"):
                metadata["target"] = str(execution_request["target"])
            if execution_request.get("tool_name"):
                metadata["tool_name"] = str(execution_request["tool_name"])
            metadata["binding_complete"] = bool(metadata.get("target") and metadata.get("tool_name"))
            approval["metadata"] = metadata
            result["approval"] = approval
            await self.approvals.save(approval)

        status = "paused" if approval else "completed"
        if result.get("terminal_reason") and not approval:
            status = "failed" if "failed" in str(result["terminal_reason"]).lower() else "completed"
        await self.checkpoints.save(incident_id, result, status=status)
        await self._flush_audit(incident_id)
        await self.incidents.commit()
        return result

    @staticmethod
    def _assert_binding(approval: Dict[str, Any], execution_request: Dict[str, Any]) -> None:
        metadata = approval.get("metadata") or {}
        if not metadata.get("binding_complete"):
            raise ValueError("approval_binding_incomplete")
        if str(approval.get("action")) != str(execution_request.get("action")):
            raise ValueError("approval_action_mismatch")
        if str(metadata.get("target")) != str(execution_request.get("target")):
            raise ValueError("approval_target_mismatch")
        if str(metadata.get("tool_name")) != str(execution_request.get("tool_name")):
            raise ValueError("approval_tool_mismatch")

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
            {"approval_id": str(approval_id), "tool_name": execution_request.get("tool_name"), "target": execution_request.get("target")},
        )

        state["approval"] = consumed
        execution_request["approval_granted"] = True
        execution_request["approval_id"] = str(approval_id)
        state["execution_request"] = execution_request
        state["current_node"] = "execution"

        orchestrator = E2EOrchestrator(db=self.session)
        result = await orchestrator._execution_node(state)
        execution_result = result.get("execution_result") or {}
        if not execution_result.get("success"):
            result["terminal_reason"] = execution_result.get("reason") or "execution_failed"
            await self.checkpoints.mark_failed(incident_id, result)
            await self._flush_audit(incident_id)
            await self.incidents.commit()
            return result

        result = await orchestrator._verification_node(result)
        verification = result.get("verification_result") or {}
        verification_status = str(verification.get("status") or "inconclusive").lower()
        if verification_status != "success":
            result["terminal_reason"] = f"verification_{verification_status}"

        result = await orchestrator._memory_node(result)
        result = await orchestrator._end_node(result)
        if verification_status == "success":
            await self.checkpoints.mark_completed(incident_id, result)
        else:
            await self.checkpoints.mark_failed(incident_id, result)
        await self.incidents.add_findings(incident_id, result.get("findings", []))
        await self._flush_audit(incident_id)
        await self.incidents.commit()
        return result
