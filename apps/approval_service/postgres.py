"""Persistence امن Approval روی PostgreSQL.

Approval یک boolean ساده نیست؛ مجوز باید durable، زمان‌دار، دارای transition محدود و
یک‌بارمصرف باشد. این store وضعیت‌های pending/approved/rejected/expired/consumed را
نگه می‌دارد تا restart، race یا replay نتواند execution را بدون مجوز معتبر عبور دهد.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from apps.approval_service.execution_claim import issue_execution_claim
from domain.contracts.config import settings


def _db_timestamp(value: Any) -> Any:
    """Normalize ISO-8601 application timestamps for asyncpg TIMESTAMPTZ binds."""
    if value is None or isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str):
        raw = value.strip()
        if not raw:
            return None
        try:
            parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValueError("invalid_approval_timestamp") from exc
    else:
        return value
    if parsed is not None and parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


class PostgreSQLApprovalStore:
    """Approval durable با expiry، transition اتمیک و consume یک‌باره قبل از execution."""

    def __init__(self, session: AsyncSession):
        self.session = session

    async def _incident_source_recovered(self, incident_id: str) -> bool:
        row = (
            await self.session.execute(
                text("SELECT status, context FROM incidents WHERE id=:id"),
                {"id": incident_id},
            )
        ).mappings().first()
        if not row:
            return False
        context = row.get("context") or {}
        if isinstance(context, str):
            try:
                context = json.loads(context)
            except json.JSONDecodeError:
                context = {}
        source_marker = dict(context.get("source_recovery") or {}) if isinstance(context, dict) else {}
        local_marker = dict(context.get("independent_recovery") or {}) if isinstance(context, dict) else {}
        return bool(
            str(row.get("status") or "").lower() == "resolved"
            and (source_marker.get("incident_resolved") or
                 local_marker.get("incident_resolved"))
        )

    async def save_validation_request(self, record: Dict[str, Any]) -> Dict[str, Any]:
        """Durably queue an immutable configuration request, NOT an Approval.

        State is pending_validation and cannot be approved by set_status().
        Never use save(): it deliberately upgrades all new records to pending.
        """
        meta = dict(record.get("metadata") or {})
        if (record.get("action") != "apply_configuration_change"
                or meta.get("workflow") != "config_change"
                or not meta.get("binding_complete")
                or not meta.get("original_sha256")
                or not meta.get("candidate_sha256")
                or not meta.get("config_file")):
            raise ValueError("invalid_config_change_request")
        if await self._incident_source_recovered(str(record.get("incident_id") or "")):
            raise ValueError("incident_already_recovered")
        now = _db_timestamp(record.get("created_at")) or datetime.now(timezone.utc)
        rows = (await self.session.execute(
            text("""
                INSERT INTO approvals
                (approval_id, incident_id, action, risk_level, approver,
                 status, metadata, created_at, approved_at, rejected_at)
                VALUES (:approval_id, :incident_id, 'apply_configuration_change',
                        'high', :approver, 'pending_validation',
                        CAST(:metadata AS jsonb), :created_at, NULL, NULL)
                ON CONFLICT DO NOTHING
                RETURNING approval_id
            """),
            {
                "approval_id": str(record["approval_id"]),
                "incident_id": str(record["incident_id"]),
                "approver": str(record["approver"]),
                "metadata": json.dumps(meta, default=str),
                "created_at": now,
            },
        )).scalars().all()
        await self.session.commit()
        if rows:
            stored = await self.get(str(rows[0]))
        else:
            matching = (await self.session.execute(
                text("""
                    SELECT approval_id FROM approvals
                    WHERE incident_id=:incident_id
                      AND action='apply_configuration_change'
                      AND metadata->>'original_sha256'=:source
                      AND metadata->>'candidate_sha256'=:candidate
                    ORDER BY created_at DESC LIMIT 1
                """),
                {
                    "incident_id": str(record["incident_id"]),
                    "source": meta["original_sha256"],
                    "candidate": meta["candidate_sha256"],
                },
            )).scalar_one_or_none()
            stored = await self.get(str(matching)) if matching else None
        if not stored:
            raise ValueError("config_change_request_persistence_failed")
        return stored

    async def record_config_validation_failure(
        self, approval_id: str, *, reason: str, guard_exit_code: int | None = None,
    ) -> Optional[Dict[str, Any]]:
        """Persist a safe diagnostic without making a request approvable.

        This is metadata-only CAS, status remains pending_validation.
        No stdout, stderr, source bytes or validator output is stored.
        """
        if not (reason.startswith("config_guard_")
                or reason in {"mcp_validation_unavailable", "validation_failed",
                              "live_source_or_candidate_drift",
                              "fresh_vendor_diagnostic_mismatch",
                              "vendor_error_changed",
                              "config_path_not_bound_to_service",
                              "config_path_not_allowlisted",
                              "unsupported_vendor_apply_adapter"}):
            reason = "config_guard_execution_failed"
        exit_code = guard_exit_code if type(guard_exit_code) is int and 0 <= guard_exit_code <= 255 else None
        patch = {
            "validation_last_reason": reason[:100],
            "validation_last_exit_code": exit_code,
            "validation_last_failed_at": datetime.now(timezone.utc).isoformat(),
        }
        row = (await self.session.execute(text("""
            UPDATE approvals
            SET metadata=COALESCE(metadata, '{}'::jsonb) || CAST(:patch AS jsonb)
            WHERE approval_id=:id
              AND status='pending_validation'
              AND action='apply_configuration_change'
              AND metadata->>'workflow'='config_change'
            RETURNING approval_id, incident_id, action, risk_level, approver,
                      status, metadata, created_at, approved_at, rejected_at
        """), {"id": approval_id, "patch": json.dumps(patch)})).mappings().first()
        await self.session.commit()
        return dict(row) if row else None

    async def promote_validated_config(
        self, approval_id: str, *, source_sha256: str,
        candidate_sha256: str, validation_scope: str, vendor_validator: str,
    ) -> Optional[Dict[str, Any]]:
        """Atomically make a real vendor-tested request human-approvable.

        This cannot skip the exact hash binding, cannot re-open terminal
        approvals, and cannot create execution authority by itself.
        """
        if validation_scope not in {
            "nginx_mount_namespace_staged_etc_nginx_live_external_read_dependencies",
            "generic_json_syntax_only_service_runtime_unverified",
            "generic_xml_syntax_only_service_runtime_unverified",
        }:
            raise ValueError("config_validation_scope_not_executable")
        current = await self.get(approval_id)
        if not current or current.get("status") != "pending_validation":
            return current
        meta = current.get("metadata") or {}
        if (meta.get("workflow") != "config_change"
                or meta.get("original_sha256") != source_sha256
                or meta.get("candidate_sha256") != candidate_sha256):
            raise ValueError("config_validation_hash_binding_mismatch")
        change = str(meta.get("proposed_change") or "")
        file_path = str(meta.get("config_file") or "")
        service = str(meta.get("service") or "").lower().removesuffix(".service")
        # A sealed complete-file LLM candidate runs the SAME independently
        # isolated vendor validator as a deterministic candidate. Restrict its
        # promotion to the matching vendor/file scope; the API checks the
        # original incident's sealed candidate and exact two SHA-256 bindings
        # before AND after the MCP validation. Do not require the historical
        # deterministic transformation name for a different candidate source.
        llm_repair = change == "llm_full_file_repair"
        if validation_scope == "generic_json_syntax_only_service_runtime_unverified":
            if (change not in {"remove_trailing_json_comma", "quote_unquoted_json_key",
                                   "repair_json_punctuation", "llm_full_file_repair"}
                    or not file_path.endswith(".json")
                    or not vendor_validator.startswith("jq empty")):
                raise ValueError("config_format_scope_mismatch")
        elif validation_scope == "generic_xml_syntax_only_service_runtime_unverified":
            if (change not in {"remove_extra_xml_closing_tag", "llm_full_file_repair"}
                    or not file_path.endswith(".xml")
                    or not vendor_validator.startswith("xmllint")):
                raise ValueError("config_xml_scope_mismatch")
        else:
            if (change not in {"remove_extra_opening_brace", "llm_full_file_repair"}
                    or service != "nginx"
                    or not file_path.endswith(".conf")
                    or (llm_repair and not file_path.startswith("/etc/nginx/"))
                    or not vendor_validator.startswith("nginx -t")):
                raise ValueError("config_vendor_scope_mismatch")
        if await self._incident_source_recovered(str(current.get("incident_id") or "")):
            raise ValueError("incident_source_already_recovered")
        proof = {
            "isolated_validation": True,
            "validation_scope": validation_scope,
            "vendor_validator": vendor_validator,
            "validation_passed_at": datetime.now(timezone.utc).isoformat(),
            "validation_last_reason": None,
            "validation_last_exit_code": None,
            "validation_last_failed_at": None,
            "request_phase": "ready_for_human_approval",
        }
        row = (await self.session.execute(
            text("""
                UPDATE approvals
                SET status='pending',
                    metadata=metadata || CAST(:proof AS jsonb)
                WHERE approval_id=:id AND status='pending_validation'
                    AND metadata->>'original_sha256'=:source
                    AND metadata->>'candidate_sha256'=:candidate
                RETURNING approval_id, incident_id, action, risk_level, approver,
                          status, metadata, created_at, approved_at, rejected_at
            """),
            {"id": approval_id, "source": source_sha256,
             "candidate": candidate_sha256, "proof": json.dumps(proof)},
        )).mappings().first()
        await self.session.commit()
        return dict(row) if row else None

    async def save(self, record: Dict[str, Any]) -> Dict[str, Any]:
        """Create durable approval authority exactly once.

        Existing approval IDs are immutable through save(): terminal states such
        as consumed/rejected/expired must never be resurrected by a repeated
        persistence call. State transitions are allowed only through the
        dedicated compare-and-set transition methods.
        """
        record_to_save = dict(record)
        # Creation is never an approval transition. New durable authority always
        # starts pending and may only become approved through set_status(), where
        # risk permission, expiry and compare-and-set transition rules are enforced.
        record_to_save["status"] = "pending"
        record_to_save["approved_at"] = None
        record_to_save["rejected_at"] = None
        metadata = dict(record.get("metadata") or {})
        if await self._incident_source_recovered(
            str(record_to_save.get("incident_id") or "")
        ):
            # A Recovery can race a slow RCA/Decision path. Persist the late
            # approval as rejected so no worker can later consume stale authority.
            record_to_save["status"] = "rejected"
            record_to_save["rejected_at"] = datetime.now(timezone.utc)
            metadata["cancelled_due_to_source_recovery"] = True

        params = dict(record_to_save)
        params["metadata"] = json.dumps(metadata, default=str)
        # ApprovalService intentionally exposes JSON-friendly ISO strings. asyncpg,
        # however, requires native datetime objects for TIMESTAMPTZ bind values.
        # Normalize exactly at the PostgreSQL adapter boundary so the domain/API
        # contract can remain serializable while persistence remains type-safe.
        params["created_at"] = (
            _db_timestamp(params.get("created_at"))
            or datetime.now(timezone.utc)
        )
        for field in ("approved_at", "rejected_at"):
            params[field] = _db_timestamp(params.get(field))
        await self.session.execute(
            text(
                """
                INSERT INTO approvals
                (approval_id, incident_id, action, risk_level, approver, status, metadata, created_at, approved_at, rejected_at)
                VALUES (:approval_id, :incident_id, :action, :risk_level, :approver, :status, CAST(:metadata AS jsonb),
                        :created_at, :approved_at, :rejected_at)
                ON CONFLICT (approval_id) DO NOTHING
                """
            ),
            params,
        )
        await self.session.commit()
        return await self.get(str(record_to_save["approval_id"])) or record_to_save

    async def _get_raw(self, approval_id: str) -> Optional[Dict[str, Any]]:
        """رکورد را بدون اعمال expiry می‌خواند؛ helper داخلی برای جلوگیری از recursion است."""
        row = (
            await self.session.execute(
                text(
                    "SELECT approval_id, incident_id, action, risk_level, approver, status, metadata, "
                    "created_at, approved_at, rejected_at FROM approvals WHERE approval_id=:id"
                ),
                {"id": approval_id},
            )
        ).mappings().first()
        return dict(row) if row else None

    @staticmethod
    def _expired(record: Dict[str, Any]) -> bool:
        """TTL را با زمان UTC محاسبه می‌کند تا timezone محلی روی مجوز اثر نگذارد."""
        created_at = record.get("created_at")
        if created_at is None or settings.APPROVAL_TTL_SECONDS <= 0:
            return False
        if isinstance(created_at, str):
            created_at = datetime.fromisoformat(created_at.replace("Z", "+00:00"))
        if created_at.tzinfo is None:
            created_at = created_at.replace(tzinfo=timezone.utc)
        return (datetime.now(timezone.utc) - created_at.astimezone(timezone.utc)).total_seconds() > settings.APPROVAL_TTL_SECONDS

    async def get(self, approval_id: str) -> Optional[Dict[str, Any]]:
        """رکورد را می‌خواند و Approval منقضی را قبل از استفاده به expired تبدیل می‌کند."""
        record = await self._get_raw(approval_id)
        if record and record.get("status") in {"pending_validation", "pending", "approved"} and self._expired(record):
            # Expiry فقط در حافظه محاسبه نمی‌شود؛ persisted شدن آن باعث می‌شود worker
            # دیگری هم همان approval را معتبر فرض نکند.
            await self.session.execute(
                text("UPDATE approvals SET status='expired' WHERE approval_id=:id AND status IN ('pending_validation','pending','approved')"),
                {"id": approval_id},
            )
            await self.session.commit()
            record = await self._get_raw(approval_id)
        return record

    async def set_status(
        self,
        approval_id: str,
        status: str,
        *,
        metadata_patch: Optional[Dict[str, Any]] = None,
    ) -> Optional[Dict[str, Any]]:
        """فقط یک Approval هنوز-pending را اتمیک به approved یا rejected transition می‌دهد."""
        if status not in {"approved", "rejected"}:
            raise ValueError("invalid_approval_status")

        # قبل از transition، get() ممکن است رکورد را expired کند. در نتیجه approval
        # منقضی هیچ‌وقت از مسیر status update به approved برنمی‌گردد.
        current = await self.get(approval_id)
        if current is None or current.get("status") != "pending":
            return current

        patch = dict(metadata_patch or {})
        patch_json = json.dumps(patch, default=str)
        timestamp_column = "approved_at" if status == "approved" else "rejected_at"
        row = (
            await self.session.execute(
                text(
                    f"""
                    UPDATE approvals
                    SET status=:status,
                        {timestamp_column}=CURRENT_TIMESTAMP,
                        metadata=COALESCE(metadata, '{{}}'::jsonb) || CAST(:metadata_patch AS jsonb)
                    WHERE approval_id=:id AND status='pending'
                    RETURNING approval_id, incident_id, action, risk_level, approver, status,
                              metadata, created_at, approved_at, rejected_at
                    """
                ),
                {"status": status, "id": approval_id, "metadata_patch": patch_json},
            )
        ).mappings().first()
        await self.session.commit()
        # شرط status='pending' خود PostgreSQL race دو approver همزمان را حل می‌کند؛
        # loser فقط وضعیت نهایی را می‌خواند و caller باید conflict را گزارش کند.
        return dict(row) if row else await self._get_raw(approval_id)

    async def cancel(
        self,
        approval_id: str,
        *,
        reason: str,
        metadata_patch: Optional[Dict[str, Any]] = None,
    ) -> Optional[Dict[str, Any]]:
        """Revoke one still-unconsumed authority token without touching peers."""
        patch = {"cancellation_reason": reason, **dict(metadata_patch or {})}
        row = (
            await self.session.execute(
                text(
                    """
                    UPDATE approvals
                    SET status='rejected',
                        rejected_at=CURRENT_TIMESTAMP,
                        metadata=COALESCE(metadata, '{}'::jsonb)
                            || CAST(:metadata_patch AS jsonb)
                    WHERE approval_id=:approval_id
                      AND status IN ('pending_validation', 'pending', 'approved')
                    RETURNING approval_id, incident_id, action, risk_level,
                              approver, status, metadata, created_at,
                              approved_at, rejected_at
                    """
                ),
                {
                    "approval_id": approval_id,
                    "metadata_patch": json.dumps(patch, default=str),
                },
            )
        ).mappings().first()
        await self.session.commit()
        return dict(row) if row else await self._get_raw(approval_id)

    async def cancel_unconsumed_for_incident(
        self,
        incident_id: str,
        *,
        reason: str,
        metadata_patch: Optional[Dict[str, Any]] = None,
    ) -> list[str]:
        """Invalidate pending/approved authority after recovery or another terminal fact."""
        patch = {"cancellation_reason": reason, **dict(metadata_patch or {})}
        rows = (
            await self.session.execute(
                text(
                    """
                    UPDATE approvals
                    SET status='rejected',
                        rejected_at=CURRENT_TIMESTAMP,
                        metadata=COALESCE(metadata, '{}'::jsonb) || CAST(:metadata_patch AS jsonb)
                    WHERE incident_id=:incident_id
                      AND status IN ('pending_validation', 'pending', 'approved')
                    RETURNING approval_id
                    """
                ),
                {
                    "incident_id": incident_id,
                    "metadata_patch": json.dumps(patch, default=str),
                },
            )
        ).scalars().all()
        await self.session.commit()
        return [str(value) for value in rows]

    async def consume(
        self,
        approval_id: str,
        *,
        issue_claim: bool = False,
    ) -> Optional[Dict[str, Any]]:
        """Claim approved authority exactly once at the execution boundary.

        Consumed means execution has claimed the approval and is about to enter
        the governed tool boundary. Before that claim, re-check source recovery
        so a missed or late cancellation cannot authorize a stale action.
        """
        current = await self.get(approval_id)
        if current is None or current.get("status") != "approved":
            # A consumed/rejected/expired approval is terminal authority and
            # must never be returned as a successful execution claim.
            return None

        incident_id = str(current.get("incident_id") or "")
        if issue_claim and incident_id:
            # Evidence and checkpoint DB triggers acquire the same row lock,
            # so their writes cannot commit between this check and consume.
            locked = (
                await self.session.execute(
                    text("SELECT id FROM incidents WHERE id=:id FOR UPDATE"),
                    {"id": incident_id},
                )
            ).scalar_one_or_none()
            if locked is None:
                raise ValueError("approval_incident_missing")

        if incident_id and await self._incident_source_recovered(incident_id):
            await self.cancel_unconsumed_for_incident(
                incident_id,
                reason="source_recovered_before_execution_claim",
                metadata_patch={
                    "cancelled_due_to_source_recovery": True,
                    "consume_blocked": True,
                },
            )
            return await self._get_raw(approval_id)

        metadata = dict(current.get("metadata") or {})
        expected = metadata.get("decision_snapshot_digest")
        if (
            issue_claim and not expected
            and metadata.get("workflow") == "e2e"
            and str(current.get("risk_level") or "").lower() in {"high", "critical"}
        ):
            # Only old E2E Incident workflow approvals require a new bound
            # Incident snapshot. Chatbot and other separately governed approval
            # families keep their own execution policy and cannot be conflated.
            return await self.cancel(
                approval_id, reason="legacy_high_risk_requires_reapproval",
                metadata_patch={"snapshot_upgrade_required": True},
            )
        if issue_claim and metadata.get("decision_snapshot_version") and not expected:
            raise ValueError("approval_snapshot_binding_incomplete")
        if issue_claim and expected:
            from apps.approval_service.binding import decision_snapshot_digest
            from apps.incident_service.repository import IncidentRepository
            from apps.orchestrator.workflow_store import WorkflowCheckpointStore

            checkpoint = await WorkflowCheckpointStore(self.session).load(incident_id) or {}
            inventory = await IncidentRepository(self.session).evidence_inventory_digest(incident_id)
            observed = decision_snapshot_digest(checkpoint.get("state") or {}, inventory)
            if observed != expected:
                row = (
                    await self.session.execute(
                        text("""
                            UPDATE approvals SET status='rejected',
                                rejected_at=CURRENT_TIMESTAMP,
                                metadata=COALESCE(metadata, '{}'::jsonb) ||
                                    CAST(:patch AS jsonb)
                            WHERE approval_id=:id AND status='approved'
                            RETURNING approval_id, incident_id, action, risk_level,
                                      approver, status, metadata, created_at, approved_at, rejected_at
                        """),
                        {
                            "id": approval_id,
                            "patch": json.dumps({
                                "cancellation_reason": "approval_decision_snapshot_changed",
                                "decision_snapshot_invalidated": True,
                                "consume_blocked": True,
                            }),
                        },
                    )
                ).mappings().first()
                await self.session.commit()
                return dict(row) if row else await self._get_raw(approval_id)

        row = (
            await self.session.execute(
                text(
                    "UPDATE approvals SET status='consumed' "
                    "WHERE approval_id=:id AND status='approved' "
                    "RETURNING approval_id, incident_id, action, risk_level, approver, status, metadata, created_at, approved_at, rejected_at"
                ),
                {"id": approval_id},
            )
        ).mappings().first()
        await self.session.commit()
        # Only the winner of the approved->consumed compare-and-set receives
        # execution authority. A concurrent/replayed loser gets no claim even
        # though the durable row is now terminally consumed.
        if not row:
            return None
        result = dict(row)
        if issue_claim:
            # Ephemeral and deliberately NOT persisted. Loading the consumed
            # approval later cannot recreate immediate execution authority.
            result["_execution_claim"] = issue_execution_claim()
        return result

    async def is_approved(self, approval_id: str) -> bool:
        """برای read-only check؛ execution واقعی همچنان باید consume اتمیک انجام دهد."""
        record = await self.get(approval_id)
        return bool(record and record.get("status") == "approved")
