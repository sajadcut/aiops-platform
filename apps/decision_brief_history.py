"""Append-only, redacted Incident Decision Brief history.

Archive only during existing persisted lifecycle transitions. Viewing reports
never writes, calls tools, publishes knowledge, or changes approval authority.
"""
from __future__ import annotations

import json
import re
from uuid import UUID, uuid4

from sqlalchemy import text

from domain.contracts.redaction import redact

_ALLOWED_EVENTS = frozenset({
    "approval_requested", "approval_approved", "approval_rejected",
    "execution_finished", "verification_finished", "direct_execution_finished",
})


async def archive_decision_brief(db, incident_id: str, event_type: str) -> str | None:
    if event_type not in _ALLOWED_EVENTS:
        raise ValueError("unsupported_decision_brief_event")
    # Use the same stable projection as the live read API and inherit
    # its redaction, source allowlist and snapshot hash.
    from apps.api.incident_resources import load_decision_brief_for_incident

    brief = await load_decision_brief_for_incident(db, UUID(str(incident_id)))
    snapshot = str(brief.get("snapshot_id") or "")
    if not re.fullmatch(r"[a-f0-9]{64}", snapshot):
        raise ValueError("invalid_decision_brief_snapshot")
    payload = redact(brief)
    encoded = json.dumps(payload, ensure_ascii=False, default=str)
    if len(encoded) > 450000:
        raise ValueError("decision_brief_snapshot_exceeds_limit")
    approval_id = (payload.get("approval_readiness") or {}).get("approval_id")
    response = await db.execute(
        text("""
            INSERT INTO incident_decision_brief_snapshots
                (id, incident_id, snapshot_hash, event_type, checkpoint_version,
                 approval_id, contract_version, brief)
            VALUES
                (:id, :incident_id, :snapshot_hash, :event_type, :checkpoint_version,
                 :approval_id, :contract_version, CAST(:brief AS jsonb))
            ON CONFLICT (incident_id, event_type, snapshot_hash) DO NOTHING
            RETURNING id
        """),
        {
            "id": str(uuid4()), "incident_id": str(incident_id),
            "snapshot_hash": snapshot, "event_type": event_type,
            "checkpoint_version": payload.get("checkpoint_version"),
            "approval_id": str(approval_id)[:128] if approval_id else None,
            "contract_version": str(payload["contract_version"])[:64],
            "brief": encoded,
        },
    )
    identifier = response.scalar_one_or_none()
    return str(identifier) if identifier else None


async def list_decision_brief_history(db, incident_id: UUID, limit: int = 30) -> list[dict]:
    if not 1 <= limit <= 100:
        raise ValueError("invalid_decision_brief_history_limit")
    result = await db.execute(text("""
        SELECT id, snapshot_hash, event_type, checkpoint_version, approval_id,
               contract_version, created_at
        FROM incident_decision_brief_snapshots
        WHERE incident_id=:incident_id
        ORDER BY created_at DESC, id DESC LIMIT :limit
    """), {"incident_id": str(incident_id), "limit": limit})
    return [
        {
            "id": str(row["id"]), "snapshot_id": row["snapshot_hash"],
            "event_type": row["event_type"], "checkpoint_version": row["checkpoint_version"],
            "approval_id": row["approval_id"], "contract_version": row["contract_version"],
            "created_at": row["created_at"].isoformat(),
        }
        for row in result.mappings()
    ]


async def read_decision_brief_snapshot(db, incident_id: UUID, snapshot_id: UUID) -> dict | None:
    result = await db.execute(text("""
        SELECT brief, snapshot_hash, contract_version
        FROM incident_decision_brief_snapshots
        WHERE id=:id AND incident_id=:incident_id
    """), {"id": str(snapshot_id), "incident_id": str(incident_id)})
    row = result.mappings().first()
    if not row:
        return None
    brief = row["brief"]
    if not isinstance(brief, dict) or brief.get("snapshot_id") != row["snapshot_hash"]:
        raise ValueError("decision_brief_snapshot_integrity_mismatch")
    return brief
