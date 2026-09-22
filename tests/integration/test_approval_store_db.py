import os
from uuid import uuid4

import pytest
from sqlalchemy import text

from apps.approval_service.postgres import PostgreSQLApprovalStore
from database import AsyncSessionLocal


pytestmark = pytest.mark.skipif(
    os.getenv("RUN_DB_APPROVAL_TEST") != "1",
    reason="requires PostgreSQL approval acceptance environment",
)


async def _seed_incident(db, incident_id):
    await db.execute(
        text(
            """
            INSERT INTO incidents
                (id, source, severity, service, status, summary)
            VALUES
                (:id, 'ci', 'medium', 'approval-test', 'OPEN', 'approval anti-replay')
            ON CONFLICT (id) DO NOTHING
            """
        ),
        {"id": incident_id},
    )
    await db.commit()


def _record(approval_id, incident_id, *, status="pending"):
    return {
        "approval_id": approval_id,
        "incident_id": incident_id,
        "action": "start_service",
        "risk_level": "medium",
        "approver": "ci",
        "status": status,
        "metadata": {
            "binding_complete": True,
            "binding_version": 1,
            "binding_digest": "test-digest",
            "environment": "test",
            "tool_name": "ssh_vm",
            "target": "vm01",
        },
        "created_at": None,
        "approved_at": None,
        "rejected_at": None,
    }


@pytest.mark.asyncio
async def test_duplicate_save_cannot_resurrect_terminal_approval_states():
    incident_id = uuid4()
    consumed_id = str(uuid4())
    rejected_id = str(uuid4())
    expired_id = str(uuid4())

    async with AsyncSessionLocal() as db:
        await _seed_incident(db, incident_id)
        store = PostgreSQLApprovalStore(db)

        await store.save(_record(consumed_id, incident_id))
        approved = await store.set_status(consumed_id, "approved")
        assert approved["status"] == "approved"
        consumed = await store.consume(consumed_id)
        assert consumed["status"] == "consumed"

        replayed = await store.save(
            _record(consumed_id, incident_id, status="approved")
        )
        assert replayed["status"] == "consumed"
        assert (await store.get(consumed_id))["status"] == "consumed"

        await store.save(_record(rejected_id, incident_id))
        rejected = await store.set_status(rejected_id, "rejected")
        assert rejected["status"] == "rejected"
        replayed_rejected = await store.save(
            _record(rejected_id, incident_id, status="approved")
        )
        assert replayed_rejected["status"] == "rejected"

        await store.save(_record(expired_id, incident_id))
        await db.execute(
            text(
                "UPDATE approvals SET status='expired' "
                "WHERE approval_id=:approval_id"
            ),
            {"approval_id": expired_id},
        )
        await db.commit()
        replayed_expired = await store.save(
            _record(expired_id, incident_id, status="approved")
        )
        assert replayed_expired["status"] == "expired"

        await db.execute(
            text("DELETE FROM approvals WHERE incident_id=:incident_id"),
            {"incident_id": incident_id},
        )
        await db.execute(
            text("DELETE FROM incidents WHERE id=:incident_id"),
            {"incident_id": incident_id},
        )
        await db.commit()
