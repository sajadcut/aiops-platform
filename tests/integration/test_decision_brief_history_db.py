"""PostgreSQL acceptance for append-only, redacted Incident Decision Brief history."""
import os
from uuid import uuid4

import pytest
from sqlalchemy import text

from apps.decision_brief_history import (
    archive_decision_brief, list_decision_brief_history,
    read_decision_brief_snapshot,
)
from apps.incident_service.repository import IncidentRepository
from database import AsyncSessionLocal


pytestmark = [
    pytest.mark.skipif(
        os.getenv("RUN_DB_DECISION_HISTORY_TEST") != "1",
        reason="requires migrated PostgreSQL acceptance database",
    ),
    pytest.mark.asyncio,
]


async def test_archive_history_is_immutable_versioned_and_incident_scoped():
    incident_id = uuid4()
    different_incident_id = uuid4()
    async with AsyncSessionLocal() as db:
        await db.execute(text("""
            INSERT INTO incidents (id, source, service, status, severity, summary)
            VALUES (:id, 'ci', 'nginx', 'OPEN', 'high', 'Nginx unavailable')
        """), {"id": str(incident_id)})
        await db.execute(text("""
            INSERT INTO incidents (id, source, service, status, severity, summary)
            VALUES (:id, 'ci', 'other-service', 'OPEN', 'medium', 'Separate incident')
        """), {"id": str(different_incident_id)})
        await db.commit()

        before = await archive_decision_brief(db, str(incident_id), "approval_requested")
        assert before is not None
        await db.commit()
        duplicate = await archive_decision_brief(db, str(incident_id), "approval_requested")
        assert duplicate is None
        await db.commit()

        await IncidentRepository(db).add_evidence(str(incident_id), [
            {"reference": "vm:nginx-status", "source": "vm_mcp",
             "type": "event", "raw_data": {
                 "diagnostic": "service_status", "active_state": "inactive",
                 "success": True,
             }},
        ])
        await db.commit()
        after = await archive_decision_brief(db, str(incident_id), "approval_approved")
        assert after is not None and after != before
        await db.commit()

        history = await list_decision_brief_history(db, incident_id)
        assert len(history) == 2
        assert history[0]["id"] == after
        assert history[0]["event_type"] == "approval_approved"
        assert history[1]["id"] == before
        latest = await read_decision_brief_snapshot(db, incident_id, uuid4())
        assert latest is None
        archived = await read_decision_brief_snapshot(db, incident_id, uuid4())
        assert archived is None
        from uuid import UUID
        saved = await read_decision_brief_snapshot(db, incident_id, UUID(before))
        assert saved is not None
        assert saved["incident_summary"]["service"] == "nginx"
        assert saved["source_policy"]["authorizes_execution"] is False
        assert (await read_decision_brief_snapshot(db, different_incident_id, UUID(before))) is None
        assert saved["snapshot_id"] == history[1]["snapshot_id"]

        # Database enforces no UPDATE, independent from read-only API policy.
        with pytest.raises(Exception, match="decision_brief_snapshot_immutable"):
            await db.execute(text("""
                UPDATE incident_decision_brief_snapshots
                SET event_type='approval_rejected' WHERE id=:id
            """), {"id": before})
            await db.commit()
        await db.rollback()


async def test_consumption_rechecks_snapshot_atomically_after_evidence_change():
    from apps.approval_service.binding import bind_metadata, decision_snapshot_digest
    from apps.approval_service.postgres import PostgreSQLApprovalStore
    from apps.orchestrator.workflow_store import WorkflowCheckpointStore

    incident_id = uuid4()
    approval_id = str(uuid4())
    state = {
        "final_plan": "start nginx after guarded approval",
        "execution_request": {
            "tool_name": "ssh_vm", "action": "start_service",
            "target": "vm01", "parameters": {"service": "nginx"},
            "timeout": 30, "runbook_id": "vm-service-recovery",
            "runbook_version": "1.1", "rollback": False,
        },
    }
    async with AsyncSessionLocal() as db:
        await db.execute(text("""
            INSERT INTO incidents(id, source, service, status, severity, summary)
            VALUES (:id, 'ci', 'nginx', 'OPEN', 'high', 'race acceptance')
        """), {"id": str(incident_id)})
        await db.commit()
        await WorkflowCheckpointStore(db).save(str(incident_id), state, status="paused")
        inventory = await IncidentRepository(db).evidence_inventory_digest(str(incident_id))
        metadata = bind_metadata(
            {}, incident_id=str(incident_id),
            **state["execution_request"],
        )
        metadata.update({
            "decision_snapshot_version": 1,
            "decision_snapshot_digest": decision_snapshot_digest(state, inventory),
            "decision_evidence_inventory_digest": inventory,
        })
        store = PostgreSQLApprovalStore(db)
        await store.save({
            "approval_id": approval_id, "incident_id": str(incident_id),
            "action": "start_service", "risk_level": "high",
            "approver": "ci", "status": "pending", "metadata": metadata,
            "created_at": None, "approved_at": None, "rejected_at": None,
        })
        approved = await store.set_status(approval_id, "approved")
        assert approved["status"] == "approved"

        # External evidence was committed AFTER approval but BEFORE claim.
        await IncidentRepository(db).add_evidence(str(incident_id), [{
            "source": "vm_mcp", "reference": "new-evidence-after-approval",
            "raw_data": {"diagnostic": "tcp_check", "reachable": False},
        }])
        await db.commit()

        revoked = await store.consume(approval_id, issue_claim=True)
        assert revoked["status"] == "rejected"
        assert revoked["metadata"]["consume_blocked"] is True
        assert "_execution_claim" not in revoked


async def test_trigger_serializes_evidence_and_checkpoint_writes_with_incident_lock():
    import asyncio
    from apps.orchestrator.workflow_store import WorkflowCheckpointStore

    incident_id = uuid4()
    async with AsyncSessionLocal() as seed:
        await seed.execute(text("""
            INSERT INTO incidents(id, source, service, status, severity, summary)
            VALUES (:id, 'ci', 'nginx', 'OPEN', 'high', 'serialize writes')
        """), {"id": str(incident_id)})
        await seed.commit()

    async def write_evidence():
        async with AsyncSessionLocal() as db:
            await IncidentRepository(db).add_evidence(str(incident_id), [{
                "source": "vm_mcp", "reference": "concurrent-status",
                "raw_data": {"diagnostic": "service_status", "active_state": "inactive"},
            }])
            await db.commit()

    async def write_checkpoint():
        async with AsyncSessionLocal() as db:
            await WorkflowCheckpointStore(db).save(
                str(incident_id), {"final_plan": "new plan"}, status="paused",
            )

    async with AsyncSessionLocal() as blocker:
        await blocker.execute(
            text("SELECT id FROM incidents WHERE id=:id FOR UPDATE"),
            {"id": str(incident_id)},
        )
        evidence_task = asyncio.create_task(write_evidence())
        checkpoint_task = asyncio.create_task(write_checkpoint())
        await asyncio.sleep(0.15)
        assert not evidence_task.done(), "evidence writer bypassed incident guard lock"
        assert not checkpoint_task.done(), "checkpoint writer bypassed incident guard lock"
        await blocker.commit()
        await asyncio.wait_for(asyncio.gather(evidence_task, checkpoint_task), timeout=8)
