from __future__ import annotations

from typing import Any, Dict

from apps.audit_service import AuditService
from apps.audit_service.postgres import PostgreSQLAuditStore
from apps.incident_service.repository import IncidentRepository
from apps.orchestrator.e2e_graph import E2EOrchestrator
from apps.orchestrator.workflow_store import WorkflowCheckpointStore
from apps.approval_service.postgres import PostgreSQLApprovalStore


class DurableWorkflowRuntime:
    """Application runtime around the LangGraph workflow.

    Incident state, findings, evidence, workflow checkpoints and primary-path
    audit events are persisted through PostgreSQL-backed stores. Approval
    resume reads the durable approval record rather than process memory.
    """

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
        status = "completed" if result.get("current_node") == "end" and not result.get("approval") else "paused"
        await self.checkpoints.save(incident_id, result, status=status)
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

        state = checkpoint["state"]
        state["approval"] = durable
        state["current_node"] = "execution"
        orchestrator = E2EOrchestrator(db=self.session)
        result = await orchestrator._execution_node(state)
        result = await orchestrator._verification_node(result)
        result = await orchestrator._memory_node(result)
        result = await orchestrator._end_node(result)
        await self.checkpoints.mark_completed(incident_id, result)
        await self.incidents.add_findings(incident_id, result.get("findings", []))
        await self._flush_audit(incident_id)
        await self.incidents.commit()
        return result
