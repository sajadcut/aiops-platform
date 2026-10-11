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
