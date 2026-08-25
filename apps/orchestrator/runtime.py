from __future__ import annotations

from typing import Any, Dict

from apps.approval_service.postgres import PostgreSQLApprovalStore
from apps.audit_service import AuditService
from apps.audit_service.postgres import PostgreSQLAuditStore
from apps.incident_service.repository import IncidentRepository
from apps.orchestrator.e2e_graph import E2EOrchestrator
from apps.orchestrator.workflow_store import WorkflowCheckpointStore


class DurableWorkflowRuntime:
    """Durable runtime for the Master incident lifecycle."""

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
        context = state.get("context", {}) or {}
        incident_context = context.get("incident", {}) or {}
        await self.incidents.upsert_incident(
            incident_id=incident_id,
            source=str(incident_context.get("source") or "api"),
            service=str(state.get("service_name") or incident_context.get("service") or "unknown"),
            severity=incident_context.get("severity"),
            summary=incident_context.get("summary") or state.get("evidence_summary"),
            status="analyzing",
            context=context,
        )
        await self.incidents.add_evidence(incident_id, state.get("live_evidence", {}).get("evidence", []))
        await self.incidents.commit()

        AuditService.record("incident_analysis_started", "durable_runtime", incident_id, status="recorded")
        result = await E2EOrchestrator(db=self.session).run(state)
        await self.incidents.add_findings(incident_id, result.get("findings", []))
        await self.incidents.add_evidence(incident_id, result.get("live_evidence", {}).get("evidence", []))

        approval = result.get("approval") or {}
        if approval:
            await self.approvals.save({
                "approval_id": str(approval["approval_id"]),
                "incident_id": incident_id,
                "action": str(approval.get("action") or state.get("execution_request", {}).get("action") or "unknown"),
                "risk_level": str(approval.get("risk_level") or result.get("decision", {}).get("risk_level") or "unknown"),
                "approver": str(approval.get("approver") or result.get("decision", {}).get("suggested_approver") or "Team-Lead"),
                "status": str(approval.get("status") or "pending"),
                "metadata": approval.get("metadata") or {},
                "created_at": approval.get("created_at"),
                "approved_at": approval.get("approved_at"),
                "rejected_at": approval.get("rejected_at"),
            })
            AuditService.record("approval_requested", "durable_runtime", incident_id, approval.get("action"), "pending", {"approval_id": approval.get("approval_id")})

        verification = result.get("verification_result") or {}
        if approval and approval.get("status") in {"pending", "requested"}:
            status = "analyzing"
        elif verification.get("status") == "success":
            status = "resolved"
        elif result.get("terminal_reason"):
            status = "escalated"
        else:
            status = "analyzing"

        await self.incidents.set_status(incident_id, status)
        workflow_status = "paused" if approval else "completed"
        await self.checkpoints.save(incident_id, result, status=workflow_status)
        await self._flush_audit(incident_id)
        await self.incidents.commit()
        return result

    async def resume_after_approval(self, incident_id: str) -> Dict[str, Any]:
        checkpoint = await self.checkpoints.load(incident_id)
        if not checkpoint:
            raise ValueError("workflow_checkpoint_not_found")

        approval = checkpoint["state"].get("approval") or {}
        approval_id = approval.get("approval_id")
        if not approval_id:
            raise ValueError("approval_not_found_in_checkpoint")

        durable = await self.approvals.get(approval_id)
        if not durable or durable.get("status") != "approved":
            raise ValueError("approval_not_granted")

        state = dict(checkpoint["state"])
        state["approval"] = durable
        state["current_node"] = "execution"
        state.setdefault("execution_request", {})["approval_id"] = approval_id
        state["execution_request"]["approval_granted"] = True
        state["execution_request"]["incident_id"] = incident_id
        state["execution_request"].setdefault("agent_name", "remediation_workflow")

        orchestrator = E2EOrchestrator(db=self.session)
        result = await orchestrator._execution_node(state)
        result = await orchestrator._verification_node(result)
        result = await orchestrator._memory_node(result)
        result = await orchestrator._end_node(result)

        verification = result.get("verification_result") or {}
        await self.incidents.set_status(
            incident_id,
            "resolved" if verification.get("status") == "success" else "escalated",
        )
        await self.checkpoints.mark_completed(incident_id, result)
        await self.incidents.add_findings(incident_id, result.get("findings", []))
        await self._flush_audit(incident_id)
        await self.incidents.commit()
        return result