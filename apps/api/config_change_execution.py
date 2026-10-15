"""Explicit two-stage governed configuration execution endpoints.

No unvalidated ticket can reach an execution boundary. Execution uses a
single-use, DB-consumed approval and an independent short-lived MCP signature.
"""
from __future__ import annotations
from uuid import UUID

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
            approved_to_review = await store.promote_validated_config(
                approval_id, source_sha256=meta["original_sha256"],
                candidate_sha256=meta["candidate_sha256"],
                validation_scope=result["validation_scope"],
                vendor_validator=result["vendor_validator"],
            )
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
        # Sign before consuming so a missing signing key cannot burn authority.
        try:
            claim, signature = create_claim(
                approval_id=id_, incident_id=str(approval["incident_id"]),
                **{k: meta[k] for k in (
                    "target", "service", "config_file", "original_sha256",
                    "candidate_sha256", "proposed_change",
                )},
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
    except Exception:
        result = {"success": False, "status": "mcp_apply_failed_or_unavailable",
                  "production_write_performed": None, "rollback_status": "unverified"}

    # No claim of recovery is made from nginx -t alone. The service is not
    # restarted automatically; a separate recovery Approval is required.
    applied = (
        result.get("success") is True and result.get("status") == "applied_verified"
        and result.get("production_write_performed") is True
        and result.get("candidate_sha256") == meta["candidate_sha256"]
    )
    async with AsyncSessionLocal() as db:
        await _audit(
            db, incident, identity.subject,
            "applied_config_vendor_verified" if applied else "config_execution_not_verified",
            {
                "approval_id": id_, "result": str(result.get("status") or "unknown")[:100],
                "rollback_status": result.get("rollback_status"),
                "production_write_performed": result.get("production_write_performed"),
                "service_recovery_confirmed": False,
            },
        )
    return {
        "approval_id": id_, "success": applied,
        "status": "applied_verified" if applied else str(result.get("status") or "execution_unverified"),
        "rollback_status": result.get("rollback_status") or "unverified",
        "config_file": meta["config_file"], "service": meta["service"],
        "target": meta["target"], "service_recovery_confirmed": False,
        "message": "Only configuration syntax and hash verified; request separate service recovery approval.",
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
