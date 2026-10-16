"""Explicit two-stage governed configuration execution endpoints.

No unvalidated ticket can reach an execution boundary. Execution uses a
single-use, DB-consumed approval and an independent short-lived MCP signature.
"""
from __future__ import annotations
from uuid import UUID

import httpx

from fastapi import APIRouter, Depends, HTTPException

from apps.approval_service.binding import assert_config_request_bound
from apps.approval_service.postgres import PostgreSQLApprovalStore
from apps.audit_service import AuditService
from apps.audit_service.postgres import PostgreSQLAuditStore
from apps.config_change_authorization import create_claim
from apps.orchestrator.workflow_store import WorkflowCheckpointStore
from apps.security.auth import require_permission
from database import AsyncSessionLocal
from integrations.vm.mcp_client import VMEdgeMCPClient

router = APIRouter()


def _fields(record: dict) -> dict:
    meta = dict(record.get("metadata") or {})
    if record.get("action") != "apply_configuration_change" or meta.get("workflow") != "config_change":
        raise HTTPException(status_code=409, detail="not_a_config_change_approval")
    if str(record.get("risk_level") or "").lower() not in {"high", "critical"}:
        raise HTTPException(status_code=409, detail="config_change_requires_high_risk_approval")
    needed = ("target", "service", "config_file", "original_sha256",
              "candidate_sha256", "proposed_change")
    if not all(meta.get(k) for k in needed):
        raise HTTPException(status_code=409, detail="incomplete_config_change_binding")
    if meta.get("tool_name") != "vm_config_change" or meta.get("runbook_id") != "vm-config-change":
        raise HTTPException(status_code=409, detail="config_change_contract_mismatch")
    parameters = {k: meta[k] for k in needed if k != "target"}
    # Pre-upgrade tickets have no recovery scope and retain their original
    # binding. New tickets bind the exact Boolean in the approval digest.
    if "start_service_after_apply" in meta:
        if type(meta["start_service_after_apply"]) is not bool:
            raise HTTPException(status_code=409, detail="config_recovery_scope_invalid")
        parameters["start_service_after_apply"] = meta["start_service_after_apply"]
    try:
        assert_config_request_bound(
            record, incident_id=str(record["incident_id"]),
            tool_name="vm_config_change", action="apply_configuration_change",
            target=meta["target"], parameters=parameters, timeout=30,
            runbook_id="vm-config-change", runbook_version="1", rollback=False,
        )
    except (ValueError, TypeError) as exc:
        raise HTTPException(status_code=409, detail="config_change_binding_changed") from exc
    return meta


async def _same_incident_candidate(db, approval: dict, meta: dict) -> bool:
    checkpoint = await WorkflowCheckpointStore(db).load(str(approval["incident_id"])) or {}
    state = checkpoint.get("state") or {}
    proposal = ((state.get("context") or {}).get("dynamic_investigation") or {}).get("config_proposal") or {}
    return (
        proposal.get("status") == "candidate_proposed"
        and proposal.get("service") == meta["service"]
        and proposal.get("config_file") == meta["config_file"]
        and proposal.get("original_sha256") == meta["original_sha256"]
        and proposal.get("candidate_sha256") == meta["candidate_sha256"]
        and proposal.get("proposed_change") == meta["proposed_change"]
        and proposal.get("execution_authority") is False
        and (meta["proposed_change"] != "llm_full_file_repair"
             or (proposal.get("candidate_stored") is True and
                 proposal.get("validation_profile") in {
                     "nginx", "json_syntax", "xml_syntax",
                 }))
    )


async def _audit(db, incident_id: str, actor: str, status: str, metadata: dict) -> None:
    AuditService.record(
        "configuration_change_transition", actor, incident_id,
        "apply_configuration_change", status, metadata,
    )
    await AuditService.flush_to_store(PostgreSQLAuditStore(db), incident_id=incident_id)


async def validate_config_ticket(approval_id: str, *, actor: str) -> dict:
    """Reconstruct the candidate on MCP worker, prove staged vendor validation."""
    async with AsyncSessionLocal() as db:
        store = PostgreSQLApprovalStore(db)
        approval = await store.get(approval_id)
        if not approval:
            raise HTTPException(status_code=404, detail="approval_not_found")
        meta = _fields(approval)
        if approval["status"] == "pending" and meta.get("isolated_validation") is True:
            return {"approval_id": approval_id, "status": "pending", "validation": "already_passed"}
        if approval["status"] != "pending_validation":
            raise HTTPException(status_code=409, detail="config_ticket_not_pending_validation")
        if not await _same_incident_candidate(db, approval, meta):
            raise HTTPException(status_code=409, detail="config_ticket_stale_incident_candidate")

    # No write capability is invoked by this endpoint.
    params = {k: meta[k] for k in (
        "service", "config_file", "original_sha256", "candidate_sha256", "proposed_change",
    )}
    try:
        result = await VMEdgeMCPClient().config_change_validate(meta["target"], **params)
    except Exception:
        result = {"success": False, "status": "mcp_validation_unavailable"}
    passed = (
        result.get("success") is True
        and result.get("isolated_validation") is True
        and result.get("status") == "isolated_vendor_validation_passed"
        and result.get("original_sha256") == meta["original_sha256"]
        and result.get("candidate_sha256") == meta["candidate_sha256"]
        and result.get("production_write_performed") is False
    )
    reason = str(result.get("status") or "validation_failed")[:100]
    async with AsyncSessionLocal() as db:
        store = PostgreSQLApprovalStore(db)
        current = await store.get(approval_id)
        if not current or current["status"] != "pending_validation":
            raise HTTPException(status_code=409, detail="config_ticket_changed_during_validation")
        live_meta = _fields(current)
        if live_meta["candidate_sha256"] != meta["candidate_sha256"] or not await _same_incident_candidate(db, current, live_meta):
            raise HTTPException(status_code=409, detail="config_candidate_changed_during_validation")
        if passed:
            # A successful vendor subprocess is not, by itself, permission
            # to upgrade an Approval ticket. If its vendor scope disagrees
            # with the original intent, keep the ticket non-approvable and
            # expose a bounded conflict instead of crashing the API with 500.
            try:
                approved_to_review = await store.promote_validated_config(
                    approval_id, source_sha256=meta["original_sha256"],
                    candidate_sha256=meta["candidate_sha256"],
                    validation_scope=str(result.get("validation_scope") or ""),
                    vendor_validator=str(result.get("vendor_validator") or ""),
                )
            except ValueError as exc:
                code = str(exc)
                if code not in {
                    "config_validation_scope_not_executable",
                    "config_validation_hash_binding_mismatch",
                    "config_format_scope_mismatch",
                    "config_xml_scope_mismatch",
                    "config_vendor_scope_mismatch",
                    "incident_source_already_recovered",
                }:
                    code = "config_validation_promotion_rejected"
                await store.record_config_validation_failure(
                    approval_id, reason="config_guard_promotion_rejected",
                    guard_exit_code=result.get("guard_exit_code"),
                )
                await _audit(db, str(current["incident_id"]), actor,
                             "validation_blocked",
                             {"approval_id": approval_id, "reason": code,
                              "isolated_validation": False,
                              "production_write_performed": False})
                raise HTTPException(status_code=409, detail=code) from exc
            if not approved_to_review or approved_to_review["status"] != "pending":
                raise HTTPException(status_code=409, detail="config_validation_transition_conflict")
        else:
            # Persist code-only failure details; stderr and config bytes stay on
            # the VM worker, and a blocked ticket NEVER becomes approvable.
            await store.record_config_validation_failure(
                approval_id, reason=reason,
                guard_exit_code=result.get("guard_exit_code"),
            )
        await _audit(db, str(current["incident_id"]), actor,
                     "pending_approval" if passed else "validation_blocked",
                     {"approval_id": approval_id, "reason": reason, "isolated_validation": passed,
                      "production_write_performed": False})
        return {
            "approval_id": approval_id,
            "status": "pending" if passed else "pending_validation",
            "validation": "passed" if passed else "blocked",
            "validation_reason": reason,
            "guard_exit_code": (
                result.get("guard_exit_code")
                if type(result.get("guard_exit_code")) is int else None
            ),
            "validation_scope": result.get("validation_scope"),
            "execution_authority": False,
            "production_write_performed": False,
        }


@router.post("/approvals/{approval_id}/validate-config")
async def validate_config(approval_id: UUID, identity=Depends(require_permission("approve:high_risk"))):
    return await validate_config_ticket(str(approval_id), actor=identity.subject)


@router.post("/approvals/{approval_id}/execute-config")
async def execute_config(approval_id: UUID, identity=Depends(require_permission("execute:approved"))):
    id_ = str(approval_id)
    async with AsyncSessionLocal() as db:
        store = PostgreSQLApprovalStore(db)
        approval = await store.get(id_)
        if not approval:
            raise HTTPException(status_code=404, detail="approval_not_found")
        meta = _fields(approval)
        if approval["status"] != "approved" or meta.get("isolated_validation") is not True:
            raise HTTPException(status_code=409, detail="config_approval_or_validation_required")
        if meta.get("validation_scope") not in {
            "nginx_mount_namespace_staged_etc_nginx_live_external_read_dependencies",
            "generic_json_syntax_only_service_runtime_unverified",
            "generic_xml_syntax_only_service_runtime_unverified",
        }:
            raise HTTPException(status_code=409, detail="unapproved_validation_scope")
        if not await _same_incident_candidate(db, approval, meta):
            raise HTTPException(status_code=409, detail="config_ticket_stale_incident_candidate")
        # A sealed model candidate has a short retention window and may
        # disappear or be invalidated after its original validation. Repeat
        # the exact read-only isolated candidate test BEFORE irrevocably
        # consuming the human Approval; production guard repeats live CAS.
        if meta.get("proposed_change") == "llm_full_file_repair":
            try:
                checked = await VMEdgeMCPClient().config_change_validate(
                    meta["target"],
                    **{key: meta[key] for key in (
                        "service", "config_file", "original_sha256",
                        "candidate_sha256", "proposed_change",
                    )},
                )
            except Exception:
                checked = {"success": False}
            if not (
                checked.get("success") is True
                and checked.get("status") == "isolated_vendor_validation_passed"
                and checked.get("isolated_validation") is True
                and checked.get("production_write_performed") is False
                and checked.get("original_sha256") == meta["original_sha256"]
                and checked.get("candidate_sha256") == meta["candidate_sha256"]
                and checked.get("validation_scope") == meta.get("validation_scope")
            ):
                raise HTTPException(status_code=409, detail="llm_candidate_revalidation_required")
        # Sign before consuming so a missing signing key cannot burn authority.
        try:
            claim, signature = create_claim(
                approval_id=id_, incident_id=str(approval["incident_id"]),
                **{k: meta[k] for k in (
                    "target", "service", "config_file", "original_sha256",
                    "candidate_sha256", "proposed_change",
                )},
                start_service_after_apply=meta.get("start_service_after_apply") is True,
            )
        except PermissionError as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from exc
        consumed = await store.consume(id_, issue_claim=True)
        if not consumed or consumed.get("status") != "consumed" or not consumed.get("_execution_claim"):
            raise HTTPException(status_code=409, detail="config_approval_not_consumable")
        incident = str(approval["incident_id"])
        await _audit(db, incident, identity.subject, "execution_claimed",
                     {"approval_id": id_, "one_time": True, "production_write_performed": False})

    try:
        result = await VMEdgeMCPClient().config_change_apply(
            meta["target"], service=meta["service"], claims=claim, signature=signature,
        )
    except Exception as exc:
        # MCPClient deliberately wraps httpx transport errors as a safe,
        # bounded RuntimeError. Preserve the underlying timeout *class* via
        # __cause__, without leaking transport traces or remote config bytes.
        # A lost write response is ambiguous: never replay a consumed Approval.
        timeout = (
            isinstance(exc, httpx.TimeoutException)
            or (isinstance(exc, RuntimeError)
                and str(exc) == "mcp_transport_error:vm-edge"
                and isinstance(exc.__cause__, httpx.TimeoutException))
        )
        result = {
            "success": False,
            "status": ("config_apply_transport_timeout_result_unknown"
                       if timeout else "mcp_apply_failed_or_unavailable"),
            "production_write_performed": None,
            "rollback_status": "unverified",
        }

    # Signed recovery scope was fixed in the original Approval metadata.
    # The VM MCP may start systemd only after successful, postchecked apply.
    # Independently reported systemd active != authoritative Zabbix recovery.
    applied = (
        result.get("success") is True and result.get("status") == "applied_verified"
        and result.get("production_write_performed") is True
        and result.get("candidate_sha256") == meta["candidate_sha256"]
    )
    recovery = result.get("service_recovery") or {}
    if not isinstance(recovery, dict):
        recovery = {}
    recovery_confirmed = bool(
        applied and meta.get("start_service_after_apply") is True
        and result.get("service_recovery_confirmed") is True
        and recovery.get("status") in {"systemd_active", "already_active"}
    )
    recovery_status = str(recovery.get("status") or "not_authorized")[:48]
    async with AsyncSessionLocal() as db:
        await _audit(
            db, incident, identity.subject,
            "applied_config_vendor_verified" if applied else "config_execution_not_verified",
            {
                "approval_id": id_, "result": str(result.get("status") or "unknown")[:100],
                "service": meta["service"], "config_file": meta["config_file"],
                "candidate_sha256": meta["candidate_sha256"],
                "rollback_status": result.get("rollback_status"),
                "production_write_performed": result.get("production_write_performed"),
                "service_recovery_confirmed": recovery_confirmed,
                "service_recovery_status": recovery_status,
                "service_start_attempted": recovery.get("attempted") is True,
                "monitor_recovery_confirmed": False,
            },
        )
    recovery_resolution = "not_verified"
    if applied:
        # The approved config write and permission to start a service are
        # different scopes. After ANY verified config apply, two independent
        # read-only VM checks may show that the original systemd-down alarm
        # has recovered (e.g. Restart=always recovers on valid JSON, or a
        # human separately starts it). No Start is issued without the signed
        # start_service_after_apply scope, and the incident closes only under
        # local_recovery_decision's separate signal/identity gates.
        from apps.incident_service.service_recovery_reconciliation import (
            reconcile_after_applied_config,
        )
        recovery_resolution = await reconcile_after_applied_config(
            incident_id=incident, target=meta["target"],
            service=meta["service"], actor=identity.subject,
        )
    knowledge_id = None
    if applied:
        # This is only a local pending human-review document. Failure to draft
        # organizational knowledge must not turn a real production change into
        # a false HTTP 500 or cause an execution retry.
        try:
            from apps.knowledge_review import create_from_verified_config_apply
            async with AsyncSessionLocal() as knowledge_db:
                review = await create_from_verified_config_apply(
                    knowledge_db, incident_id=UUID(incident), approval_id=id_)
                knowledge_id = str(review.id) if review else None
        except Exception:
            from domain.contracts.logging import logger
            logger.warning("config_apply_knowledge_draft_failed",
                           incident_id=incident, approval_id=id_)
    return {
        "knowledge_review_id": knowledge_id,
        "incident_recovery_status": recovery_resolution,
        "incident_resolved": recovery_resolution == "resolved_independent_vm_verified",
        "approval_id": id_, "success": applied,
        "status": "applied_verified" if applied else str(result.get("status") or "execution_unverified"),
        "rollback_status": result.get("rollback_status") or "unverified",
        "config_file": meta["config_file"], "service": meta["service"],
        "target": meta["target"], "service_recovery_confirmed": recovery_confirmed,
        "service_recovery_status": recovery_status,
        "service_start_attempted": recovery.get("attempted") is True,
        "monitor_recovery_confirmed": False,
        "message": (
            "Configuration applied; two independent systemd checks verified "
            "recovery and the service-down incident was resolved locally. "
            "No Zabbix recovery event was fabricated."
            if recovery_resolution == "resolved_independent_vm_verified"
            else "Configuration applied and systemd is running, but incident "
                 "resolution is gated by the original alert and correlated signals."
            if recovery_confirmed
            else "Configuration apply failed or its result could not be verified. "
                 "The approval has been consumed; check the live file hash, "
                 "service state and execution audit before issuing a new "
                 "human-approved change. No Start was authorized or verified."
        ),
    }

@router.post("/approvals/{approval_id}/reject-config")
async def reject_pending_config(approval_id: UUID, identity=Depends(require_permission("approve:high_risk"))):
    async with AsyncSessionLocal() as db:
        store = PostgreSQLApprovalStore(db)
        approval = await store.get(str(approval_id))
        if not approval:
            raise HTTPException(status_code=404, detail="approval_not_found")
        _fields(approval)
        if approval["status"] != "pending_validation":
            raise HTTPException(status_code=409, detail="config_rejection_state_changed")
        changed = await store.cancel(
            str(approval_id), reason="rejected_by_operator_before_validation",
            metadata_patch={"rejected_by": identity.subject},
        )
        if not changed or changed.get("status") != "rejected":
            raise HTTPException(status_code=409, detail="config_rejection_conflict")
        await _audit(db, str(approval["incident_id"]), identity.subject,
                     "config_change_rejected", {"approval_id": str(approval_id),
                     "production_write_performed": False})
        return {"status": "rejected", "approval_id": str(approval_id)}
