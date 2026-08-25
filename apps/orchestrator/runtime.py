from __future__ import annotations

import json
from typing import Any, Dict, List

from apps.approval_service.postgres import PostgreSQLApprovalStore
from apps.audit_service import AuditService
from apps.audit_service.postgres import PostgreSQLAuditStore
from apps.incident_service.repository import IncidentRepository
from apps.orchestrator.e2e_graph import E2EOrchestrator
from apps.orchestrator.workflow_store import WorkflowCheckpointStore
from sqlalchemy import text


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

    async def _persist_governance(self, incident_id: str, result: Dict[str, Any]) -> None:
        plan = result.get("final_plan")
        if plan:
            evidence_ids: List[str] = []
            for finding in result.get("findings", []):
                evidence_ids.extend(str(item) for item in (finding.get("evidence_ids") or []))
            await self.session.execute(
                text(
                    """
                    INSERT INTO action_plans (incident_id, plan, confidence, evidence_ids, status)
                    VALUES (:incident_id, :plan, :confidence, CAST(:evidence_ids AS jsonb), :status)
                    """
                ),
                {
                    "incident_id": incident_id,
                    "plan": str(plan),
                    "confidence": float(result.get("confidence") or 0.0),
                    "evidence_ids": json.dumps(sorted(set(evidence_ids))),
                    "status": "approved" if result.get("approval") else "proposed",
                },
            )
            AuditService.record("action_plan_persisted", "durable_runtime", incident_id, str(plan)[:255], "recorded")

        decision = result.get("decision") or {}
        if decision:
            await self.session.execute(
                text(
                    """
                    INSERT INTO policy_decisions
                        (incident_id, action, risk_level, reason, requires_approval, metadata)
                    VALUES (:incident_id, :action, :risk_level, :reason, :requires_approval, CAST(:metadata AS jsonb))
                    """
                ),
                {
                    "incident_id": incident_id,
                    "action": str(decision.get("action") or "unknown"),
                    "risk_level": str(decision.get("risk_level") or "unknown"),
                    "reason": str(decision.get("reason") or "No reason supplied"),
                    "requires_approval": bool(decision.get("requires_approval", True)),
                    "metadata": json.dumps(decision.get("metadata") or {}, default=str),
                },
            )
            AuditService.record("policy_decision_persisted", "durable_runtime", incident_id, str(decision.get("action")), "recorded")

        verification = result.get("verification_result") or {}
        if verification:
            await self.session.execute(
                text(
                    """
                    INSERT INTO verification_results
                        (incident_id, status, before_state, after_state, changes, confidence, evidence_refs, message)
                    VALUES
                        (:incident_id, :status, CAST(:before_state AS jsonb), CAST(:after_state AS jsonb),
                         CAST(:changes AS jsonb), :confidence, CAST(:evidence_refs AS jsonb), :message)
                    """
                ),
                {
                    "incident_id": incident_id,
                    "status": str(verification.get("status") or "inconclusive"),
                    "before_state": json.dumps(verification.get("before_state") or {}, default=str),
                    "after_state": json.dumps(verification.get("after_state") or {}, default=str),
                    "changes": json.dumps(verification.get("changes") or [], default=str),
                    "confidence": float(verification.get("confidence") or 0.0),
                    "evidence_refs": json.dumps(verification.get("evidence_refs") or [], default=str),
                    "message": verification.get("message"),
                },
            )
            AuditService.record("verification_persisted", "durable_runtime", incident_id, None, "recorded")

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
        await self._persist_governance(incident_id, result)

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
        await self._persist_governance(incident_id, result)

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