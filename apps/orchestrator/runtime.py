from __future__ import annotations

from typing import Any, Dict, Type

from apps.approval_service.binding import assert_bound, bind_metadata
from apps.approval_service.postgres import PostgreSQLApprovalStore
from apps.audit_service import AuditService
from apps.audit_service.postgres import PostgreSQLAuditStore
from apps.incident_service.repository import IncidentRepository
from apps.orchestrator.e2e_graph import E2EOrchestrator
from apps.orchestrator.signal_aware import SignalAwareE2EOrchestrator
from apps.orchestrator.workflow_store import WorkflowCheckpointStore
from apps.runbook_service.runtime_guard import RunbookRuntimeGuard
from integrations.vm.target_context import bind_vm_port, bind_vm_target, reset_vm_port, reset_vm_target


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
            source=fields["source"], service=fields["service"], severity=fields["severity"],
            summary=fields["summary"], status="analyzing", context=fields["context"],
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
            if not execution_request:
                raise ValueError("approval_execution_request_missing")
            approval["metadata"] = bind_metadata(
                dict(approval.get("metadata") or {}), incident_id=incident_id,
                tool_name=execution_request.get("tool_name"), action=execution_request.get("action"),
                target=execution_request.get("target"), parameters=execution_request.get("parameters", {}),
                timeout=execution_request.get("timeout", 30), runbook_id=execution_request.get("runbook_id"),
                runbook_version=execution_request.get("runbook_version"), rollback=execution_request.get("rollback", False),
            )
            result["approval"] = approval
            await self.approvals.save(approval)

        checkpoint_status = "paused" if approval else "completed"
        if result.get("terminal_reason") and not approval:
            checkpoint_status = "failed" if "failed" in str(result["terminal_reason"]).lower() else "completed"
        await self.checkpoints.save(incident_id, result, status=checkpoint_status)

        final_fields = self._incident_fields(result)
        await self.incidents.upsert_incident(
            incident_id=incident_id, source=final_fields["source"], service=final_fields["service"],
            severity=final_fields["severity"], summary=final_fields["summary"],
            status=self._final_incident_status(result), context=final_fields["context"],
        )
        await self._flush_audit(incident_id)
        await self.incidents.commit()
        return result

    @staticmethod
    def _assert_binding(approval: Dict[str, Any], execution_request: Dict[str, Any]) -> None:
        assert_bound(
            approval, incident_id=approval.get("incident_id"), tool_name=execution_request.get("tool_name"),
            action=execution_request.get("action"), target=execution_request.get("target"),
            parameters=execution_request.get("parameters", {}), timeout=execution_request.get("timeout", 30),
            runbook_id=execution_request.get("runbook_id"), runbook_version=execution_request.get("runbook_version"),
            rollback=execution_request.get("rollback", False),
        )

    @staticmethod
    def _bind_execution_context(execution_request: Dict[str, Any]):
        """Restore request-scoped VM identity after a durable approval pause.

        Signal ingestion contextvars intentionally expire with the webhook request.
        The persisted execution request is approval-bound, so it is the correct
        source for re-establishing the exact VM target/port while refreshing
        pre/post execution evidence after a later approval request.
        """
        if str(execution_request.get("tool_name") or "") != "ssh_vm":
            return None
        target = str(execution_request.get("target") or "").strip()
        parameters = dict(execution_request.get("parameters") or {})
        raw_port = parameters.get("target_port")
        port = None
        if raw_port not in (None, ""):
            try:
                candidate = int(raw_port)
                if 1 <= candidate <= 65535:
                    port = candidate
            except (TypeError, ValueError):
                port = None
        target_token = bind_vm_target(target)
        port_token = bind_vm_port(port)
        return target_token, port_token

    @staticmethod
    def _reset_execution_context(tokens) -> None:
        if tokens is None:
            return
        target_token, port_token = tokens
        reset_vm_port(port_token)
        reset_vm_target(target_token)

    async def _preconsume_execution_guard(
        self,
        incident_id: str,
        approval_id: str,
        execution_request: Dict[str, Any],
        state: Dict[str, Any],
    ) -> None:
        """Revalidate supported write intent before consuming approval authority."""
        runbook_id = str(execution_request.get("runbook_id") or "").strip()
        if runbook_id != RunbookRuntimeGuard.VM_SERVICE_RUNBOOK:
            return

        target = str(execution_request.get("target") or "").strip()
        parameters = dict(execution_request.get("parameters") or {})
        tokens = self._bind_execution_context(execution_request)
        try:
            snapshot = await RunbookRuntimeGuard.collect_snapshot(
                runbook_id=runbook_id,
                target=target,
                parameters=parameters,
                incident_id=incident_id,
                phase="approval_preconsume",
            )
        finally:
            self._reset_execution_context(tokens)

        precondition = RunbookRuntimeGuard.preflight(
            runbook_id=runbook_id,
            tool_name=str(execution_request.get("tool_name") or ""),
            action=str(execution_request.get("action") or ""),
            target=target,
            parameters=parameters,
            incident_id=incident_id,
            evidence=list(snapshot.get("evidence") or []),
        )
        state["approval_precondition"] = precondition
        state.setdefault("context", {})["approval_preconsume_snapshot"] = {
            "read_success": bool(snapshot.get("read_success")),
            "error": snapshot.get("error"),
            "evidence": list(snapshot.get("evidence") or []),
        }

        if precondition.get("safe_to_execute"):
            AuditService.record(
                "approval_precondition_verified",
                "durable_runtime",
                incident_id,
                execution_request.get("action"),
                "recorded",
                {
                    "approval_id": approval_id,
                    "runbook_id": runbook_id,
                    "evidence_refs": precondition.get("evidence_refs", []),
                },
            )
            return

        reason = str(
            precondition.get("reason") or "runtime_precondition_failed"
        )
        stale = RunbookRuntimeGuard.approval_should_be_revoked(precondition)
        if stale:
            revoked = await self.approvals.cancel(
                approval_id,
                reason="fresh_precondition_invalidated_approved_intent",
                metadata_patch={
                    "precondition_reason": reason,
                    "revoked_before_execution": True,
                },
            )
            if revoked is not None:
                state["approval"] = revoked
            state["execution_result"] = {
                "success": False,
                "tool_name": execution_request.get("tool_name"),
                "action": execution_request.get("action"),
                "target": execution_request.get("target"),
                "execution_blocked": True,
                "reason": reason,
            }
            state["terminal_reason"] = "approval_preflight_stale"
            AuditService.record(
                "approval_precondition_stale",
                "durable_runtime",
                incident_id,
                execution_request.get("action"),
                "blocked",
                {
                    "approval_id": approval_id,
                    "runbook_id": runbook_id,
                    "reason": reason,
                    "approval_revoked": bool(
                        revoked and revoked.get("status") == "rejected"
                    ),
                },
            )
            await self.checkpoints.mark_failed(incident_id, state)
            await self._flush_audit(incident_id)
            await self.incidents.commit()
            raise ValueError(f"approval_preflight_stale:{reason}")

        AuditService.record(
            "approval_precondition_retryable",
            "durable_runtime",
            incident_id,
            execution_request.get("action"),
            "blocked",
            {
                "approval_id": approval_id,
                "runbook_id": runbook_id,
                "reason": reason,
                "approval_revoked": False,
            },
        )
        await self._flush_audit(incident_id)
        await self.incidents.commit()
        raise ValueError(f"approval_preflight_retryable:{reason}")

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
        await self._preconsume_execution_guard(
            incident_id,
            str(approval_id),
            execution_request,
            state,
        )

        consumed = await self.approvals.consume(str(approval_id), issue_claim=True)
        if not consumed or consumed.get("status") != "consumed":
            raise ValueError("approval_already_consumed")
        AuditService.record(
            "approval_consumed", "durable_runtime", incident_id, execution_request.get("action"), "recorded",
            {"approval_id": str(approval_id), "tool_name": execution_request.get("tool_name"), "target": execution_request.get("target")},
        )

        state["approval"] = consumed
        execution_request["approval_granted"] = True
        execution_request["approval_id"] = str(approval_id)
        execution_request["incident_id"] = incident_id
        execution_request["execution_claim"] = consumed.get("_execution_claim")
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
            result["terminal_reason"] = execution_result.get("reason") or "execution_failed"
            # Negative governed outcomes are still durable Operational Memory.
            # This does not resolve the incident; it records the failed/blocked
            # attempt and allows cited historical experience to receive negative
            # reuse feedback.
            result = await orchestrator._memory_node(result)
            result = await orchestrator._end_node(result)
            await self.checkpoints.mark_failed(incident_id, result)
            await self._set_incident_status(incident_id, "escalated")
            await self.incidents.add_findings(
                incident_id,
                result.get("findings", []),
            )
            await self._flush_audit(incident_id)
            await self.incidents.commit()
            return result

        verification_tokens = self._bind_execution_context(execution_request)
        try:
            result = await orchestrator._verification_node(result)
        finally:
            self._reset_execution_context(verification_tokens)
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
                incident_id=incident_id, source=final_fields["source"], service=final_fields["service"],
                severity=final_fields["severity"], summary=final_fields["summary"],
                status="resolved" if verification_status == "success" else "escalated", context=final_fields["context"],
            )
        await self._flush_audit(incident_id)
        await self.incidents.commit()
        return result
