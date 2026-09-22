import asyncio
import os
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest
from sqlalchemy import text

from apps.approval_service.postgres import PostgreSQLApprovalStore
from database import AsyncSessionLocal


pytestmark = [
    pytest.mark.skipif(
        os.getenv("RUN_DB_APPROVAL_TEST") != "1",
        reason="requires PostgreSQL approval acceptance environment",
    ),
    pytest.mark.asyncio(loop_scope="module"),
]


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


@pytest.mark.asyncio(loop_scope="module")
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

        # Creation cannot inject already-approved authority. save() is create-only;
        # the approval transition must still go through set_status().
        injected_id = str(uuid4())
        injected = await store.save(
            _record(injected_id, incident_id, status="approved")
        )
        assert injected["status"] == "pending"
        injected_approved = await store.set_status(injected_id, "approved")
        assert injected_approved["status"] == "approved"

        # A committed source recovery between approval and consume invalidates the
        # authority before the execution boundary can be claimed.
        recovered_id = str(uuid4())
        await store.save(_record(recovered_id, incident_id))
        recovered_approved = await store.set_status(recovered_id, "approved")
        assert recovered_approved["status"] == "approved"
        await db.execute(
            text(
                """
                UPDATE incidents
                SET status='RESOLVED',
                    context=jsonb_build_object(
                        'source_recovery',
                        jsonb_build_object('incident_resolved', true)
                    )
                WHERE id=:incident_id
                """
            ),
            {"incident_id": incident_id},
        )
        await db.commit()
        blocked = await store.consume(recovered_id)
        assert blocked["status"] == "rejected"
        assert blocked["metadata"]["cancelled_due_to_source_recovery"] is True
        assert blocked["metadata"]["consume_blocked"] is True

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

        # Isolate TTL semantics from the source-recovery scenario above.
        await db.execute(
            text(
                "UPDATE incidents SET status='OPEN', context='{}'::jsonb "
                "WHERE id=:incident_id"
            ),
            {"incident_id": incident_id},
        )
        await db.commit()

        # Expiry is enforced from created_at before approval/consume can be used.
        ttl_id = str(uuid4())
        ttl_record = _record(ttl_id, incident_id)
        ttl_record["created_at"] = (
            datetime.now(timezone.utc)
            - timedelta(seconds=10_000)
        ).isoformat()
        await store.save(ttl_record)
        ttl_read = await store.get(ttl_id)
        assert ttl_read["status"] == "expired"
        ttl_approve = await store.set_status(ttl_id, "approved")
        assert ttl_approve["status"] == "expired"

        # Approved authority is single-use. A second consume must observe the
        # already-consumed terminal state and cannot claim execution again.
        once_id = str(uuid4())
        await store.save(_record(once_id, incident_id))
        once_approved = await store.set_status(once_id, "approved")
        assert once_approved["status"] == "approved"
        first_consume = await store.consume(
            once_id,
            issue_claim=True,
        )
        assert first_consume["status"] == "consumed"
        assert first_consume.get("_execution_claim")
        second_consume = await store.consume(
            once_id,
            issue_claim=True,
        )
        assert second_consume is None
        durable_once = await store.get(once_id)
        assert durable_once["status"] == "consumed"
        assert "_execution_claim" not in durable_once

        await db.execute(
            text("DELETE FROM approvals WHERE incident_id=:incident_id"),
            {"incident_id": incident_id},
        )
        await db.execute(
            text("DELETE FROM incidents WHERE id=:incident_id"),
            {"incident_id": incident_id},
        )
        await db.commit()


@pytest.mark.asyncio(loop_scope="module")
async def test_concurrent_consume_has_exactly_one_execution_authority_winner():
    incident_id = uuid4()
    approval_id = str(uuid4())

    async with AsyncSessionLocal() as db:
        await _seed_incident(db, incident_id)
        store = PostgreSQLApprovalStore(db)
        await store.save(_record(approval_id, incident_id))
        approved = await store.set_status(approval_id, "approved")
        assert approved["status"] == "approved"

    async def claim():
        async with AsyncSessionLocal() as session:
            return await PostgreSQLApprovalStore(session).consume(
                approval_id,
                issue_claim=True,
            )

    first, second = await asyncio.gather(claim(), claim())
    winners = [
        result
        for result in (first, second)
        if result is not None and result.get("status") == "consumed"
    ]
    losers = [result for result in (first, second) if result is None]

    assert len(winners) == 1
    assert len(losers) == 1
    assert winners[0].get("_execution_claim")

    async with AsyncSessionLocal() as db:
        store = PostgreSQLApprovalStore(db)
        durable = await store.get(approval_id)
        assert durable["status"] == "consumed"
        assert "_execution_claim" not in durable

        await db.execute(
            text("DELETE FROM approvals WHERE approval_id=:approval_id"),
            {"approval_id": approval_id},
        )
        await db.execute(
            text("DELETE FROM incidents WHERE id=:incident_id"),
            {"incident_id": incident_id},
        )
        await db.commit()
