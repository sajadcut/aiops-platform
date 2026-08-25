from __future__ import annotations

from typing import Any, Dict, Type

from apps.approval_service.postgres import PostgreSQLApprovalStore
from apps.audit_service import AuditService
from apps.audit_service.postgres import PostgreSQLAuditStore
from apps.incident_service.repository import IncidentRepository
from apps.orchestrator.e2e_graph import E2EOrchestrator
from apps.orchestrator.signal_aware import SignalAwareE2EOrchestrator
from apps.orchestrator.workflow_store import WorkflowCheckpointStore


class DurableWorkflowRuntime:
    """PostgreSQL-backed runtime around the governed collaborative LangGraph workflow."""

    def __init__(self, session, orchestrator_cls: Type[E2EOrchestrator] = SignalAwareE2EOrchestrator):
        self.session = session
        self.orchestrator_cls = orchestrator_cls
        self.checkpoints = WorkflowCheckpointStore(session)
        self.incidents = IncidentRepository(session)
        self.approvals = PostgreSQLApprovalStore(session)
        self.audit = PostgreSQLAuditStore(session)

    def _orchestrator_type(self) -> Type[E2EOrchestrator]:
        return getattr(self, "orchestrator_cls", E2EOrchestrator)

    async def _flush_audit(self, incident_id: str) -> None:
        await AuditService.flush_to_store(self.audit, incident_id=incident_id)

    async def _set_incident_status(self, incident_id: str, status: str) -> None:
        """Persist lifecycle state when the repository supports it.

        The capability check keeps small focused test doubles and third-party
        repository adapters backward-compatible without weakening the normal
        PostgreSQL runtime, whose IncidentRepository always implements it.
        """
        setter = getattr(self.incidents, "set_status", None)
        if callable(setter):
            await setter(incident_id, status)

    @staticmethod
    def _incident_fields(state: Dict[str, Any]) -> Dict[str, Any]:
        context = dict(state.get("context") or {})
        incident = dict(context.get("incident") or {})
        return {
            "source": str(incident.get("source") or "api"),
            "service": str(state.get("service_name") or context.get("service") or "unknown"),
            "severity": incident.get("severity"),
            "summary": incident.get("summary") or state.get("evidence_summary"),
            "context": context,
        }

    @staticmethod
    def _final_incident_status(result: Dict[str, Any]) -> str:
        if result.get("approval"):
            return "analyzing"
        verification = str((result.get("verification_result") or {}).get("status") or "").lower()
        if verification == "success":
            return "resolved"
        execution = result.get("execution_result") or {}
        if execution and not execution.get("success"):
            return "escalated"
        if result.get("execution_request") and result.get("terminal_reason"):
            return "escalated"
        return "open"

    async def start(self, state: Dict[str, Any]) -> Dict[str, Any]:
        incident_id = str(state["incident_id"])
        fields = self._incident_fields(state)
        await self.incidents.upsert_incident(
            incident_id=incident_id,
            source=fields["source"],
            service=fields["service"],
            severity=fields["severity"],
            summary=fields["summary"],
            status="analyzing",
            context=fields["context"],
        )
        seed_evidence = list(state.get("context", {}).get("trigger_evidence", []) or [])
        if seed_evidence:
            await self.incidents.add_evidence(incident_id, seed_evidence)
        await self.incidents.add_evidence(incident_id, state.get("live_evidence", {}).get("evidence", []))
        await self.incidents.commit()

        result = await self._orchestrator_type()(db=self.session).run(state)
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

        checkpoint_status = "paused" if approval else "completed"
        if result.get("terminal_reason") and not approval:
            checkpoint_status = "failed" if "failed" in str(result["terminal_reason"]).lower() else "completed"
        await self.checkpoints.save(incident_id, result, status=checkpoint_status)

        final_fields = self._incident_fields(result)
        await self.incidents.upsert_incident(
            incident_id=incident_id,
            source=final_fields["source"],
            service=final_fields["service"],
            severity=final_fields["severity"],
            summary=final_fields["summary"],
            status=self._final_incident_status(result),
            context=final_fields["context"],
        )
        await self._flush_audit(incident_id)
        await self.incidents.commit()
        return result

    @staticmethod
    def _assert_binding(approval: Dict[str, Any], execution_request: Dict[str, Any]) -> None:
        metadata = approval.get("metadata") or {}
        if not metadata.get("target") or not metadata.get("tool_name"):
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

        orchestrator = self._orchestrator_type()(db=self.session)
        result = await orchestrator._execution_node(state)
        execution_result = result.get("execution_result") or {}
        if not execution_result.get("success"):
            result["terminal_reason"] = execution_result.get("reason") or "execution_failed"
            await self.checkpoints.mark_failed(incident_id, result)
            await self._set_incident_status(incident_id, "escalated")
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
            await self._set_incident_status(incident_id, "resolved")
        else:
            await self.checkpoints.mark_failed(incident_id, result)
            await self._set_incident_status(incident_id, "escalated")
        await self.incidents.add_findings(incident_id, result.get("findings", []))
        upsert = getattr(self.incidents, "upsert_incident", None)
        if callable(upsert):
            final_fields = self._incident_fields(result)
            await upsert(
                incident_id=incident_id,
                source=final_fields["source"],
                service=final_fields["service"],
                severity=final_fields["severity"],
                summary=final_fields["summary"],
                status="resolved" if verification_status == "success" else "escalated",
                context=final_fields["context"],
            )
        await self._flush_audit(incident_id)
        await self.incidents.commit()
        return result
