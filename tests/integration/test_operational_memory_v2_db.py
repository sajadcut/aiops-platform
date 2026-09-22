import os
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest
from sqlalchemy import select

from apps.memory_service import OperationalMemoryService
from apps.memory_service.builder import OperationalMemoryBuilder
from database import AsyncSessionLocal
from domain.contracts.config import settings
from domain.models import MemoryEntry, MemoryReuseEvent
from knowledge import EmbeddingService


pytestmark = pytest.mark.skipif(
    os.getenv("RUN_DB_MEMORY_V2_TEST") != "1",
    reason="requires PostgreSQL/pgvector database acceptance environment",
)


def _state(incident_id: str, *, success: bool = True):
    return {
        "incident_id": incident_id,
        "service_name": "nginx",
        "evidence_summary": "nginx inactive port 86 unavailable tcp unreachable",
        "context": {
            "incident": {
                "source": "ci",
                "summary": "nginx port 86 unavailable",
                "severity": "medium",
            },
            "trigger_signal": {
                "source": "ci",
                "signal_type": "port_down",
                "summary": "nginx port 86 unavailable",
            },
            "evidence": [
                {
                    "source": "ci-vm",
                    "type": "event",
                    "reference": f"ci:{incident_id}:service",
                }
            ],
        },
        "findings": [
            {
                "agent_name": "vm",
                "statement": "nginx is inactive; historical reason is not proven",
                "confidence": 0.9,
                "evidence_ids": [f"ci:{incident_id}:service"],
            }
        ],
        "execution_request": {
            "tool_name": "ssh_vm",
            "action": "start_service",
            "target": "10.0.0.10",
            "parameters": {"service": "nginx", "target_port": 86},
            "runbook_id": "vm-service-recovery",
            "runbook_version": "1.1",
        },
        "execution_result": {
            "success": success,
            "tool_name": "ssh_vm",
            "action": "start_service",
            "target": "10.0.0.10",
            "reason": None if success else "service_start_failed",
        },
        "verification_result": {
            "status": "success" if success else "failed",
            "confidence": 0.92 if success else 0.9,
            "before_state": {
                "service_active": 0,
                "port_listening": 0,
                "tcp_reachable": 0,
            },
            "after_state": {
                "service_active": 1 if success else 0,
                "port_listening": 1 if success else 0,
                "tcp_reachable": 1 if success else 0,
            },
            "metric_directions": {
                "service_active": "higher_is_better",
                "port_listening": "higher_is_better",
                "tcp_reachable": "higher_is_better",
            },
            "evidence_refs": [f"ci:{incident_id}:service"],
            "message": "verified recovery" if success else "recovery failed",
        },
    }


@pytest.mark.asyncio
async def test_memory_v2_lexical_retrieval_survives_embedding_provider_outage(monkeypatch):
    incident_id = str(uuid4())

    async with AsyncSessionLocal() as db:
        service = OperationalMemoryService(db)
        episode = OperationalMemoryBuilder.build(
            _state(incident_id, success=True)
        )
        memory_id = await service.add_episode(episode)

        async def embedding_down(_text):
            raise RuntimeError("embedding-provider-down")

        monkeypatch.setattr(
            EmbeddingService,
            "generate_embedding",
            embedding_down,
        )

        results = await service.retrieve(
            "nginx inactive port 86 unavailable",
            service_scope="nginx",
            environment="test",
            retrieval_mode="SIMILAR_INCIDENT",
            limit=10,
            successful_only=False,
        )

        assert str(memory_id) in {item["id"] for item in results}
        match = next(item for item in results if item["id"] == str(memory_id))
        assert match["lexical_score"] > 0
        assert match["safe_as_evidence"] is False
        assert match["requires_current_validation"] is True


@pytest.mark.asyncio
async def test_memory_v2_postgres_hybrid_retrieval_and_feedback():
    successful_incident = str(uuid4())
    failed_incident = str(uuid4())
    target_incident = str(uuid4())

    async with AsyncSessionLocal() as db:
        service = OperationalMemoryService(db)

        success_episode = OperationalMemoryBuilder.build(
            _state(successful_incident, success=True)
        )
        failed_episode = OperationalMemoryBuilder.build(
            _state(failed_incident, success=False)
        )
        success_id = await service.add_episode(success_episode)
        failed_id = await service.add_episode(failed_episode)
        duplicate_id = await service.add_episode(success_episode)
        assert duplicate_id == success_id

        duplicate_rows = (
            await db.execute(
                select(MemoryEntry).where(
                    MemoryEntry.episode_fingerprint
                    == success_episode["episode_fingerprint"]
                )
            )
        ).scalars().all()
        assert len(duplicate_rows) == 1

        success_row = await db.get(MemoryEntry, success_id)
        assert success_row is not None
        assert success_row.episode_fingerprint == success_episode["episode_fingerprint"]
        assert success_row.embedding is not None
        assert success_row.embedding_status == "ready"
        assert success_row.actual_remediation["action"] == "start_service"

        results = await service.retrieve(
            "nginx inactive port 86 tcp unreachable",
            service_scope="nginx",
            environment="test",
            retrieval_mode="SIMILAR_INCIDENT",
            limit=10,
            successful_only=False,
            target_incident_id=target_incident,
            record_retrieval=True,
        )
        ids = {item["id"] for item in results}
        assert str(success_id) in ids
        assert str(failed_id) in ids
        assert all(item["safe_as_evidence"] is False for item in results)
        assert all(item["requires_current_validation"] is True for item in results)

        remediation = await service.retrieve(
            "nginx inactive port unavailable",
            service_scope="nginx",
            retrieval_mode="REMEDIATION_EXPERIENCE",
            limit=10,
            successful_only=False,
        )
        by_id = {item["id"]: item for item in remediation}
        assert by_id[str(success_id)]["memory_outcome_class"] == "successful_recovery"
        assert by_id[str(failed_id)]["memory_outcome_class"] == "failed_recovery"

        # Retrieve the same episode through a second mode before feedback.
        # Feedback may annotate both retrieval events, but MemoryEntry reward
        # counters must advance only once for this target incident.
        await service.retrieve(
            "nginx inactive port unavailable start service",
            service_scope="nginx",
            retrieval_mode="REMEDIATION_EXPERIENCE",
            limit=10,
            successful_only=False,
            target_incident_id=target_incident,
            record_retrieval=True,
        )
        before_reward = int(success_row.successful_reuse_count or 0)
        updated = await service.record_feedback(
            target_incident,
            execution_request={"action": "start_service"},
            verification_result={"status": "success"},
            cited_memory_ids=[str(success_id)],
        )
        assert updated >= 1

        events = (
            await db.execute(
                select(MemoryReuseEvent).where(
                    MemoryReuseEvent.target_incident_id == target_incident
                )
            )
        ).scalars().all()
        assert events
        assert any(event.action_executed for event in events)
        assert any(event.was_cited_by_agent for event in events)
        assert any(event.influenced_plan for event in events)
        refreshed = await db.get(MemoryEntry, success_id)
        assert refreshed is not None
        assert int(refreshed.successful_reuse_count or 0) == before_reward + 1
        assert refreshed.effectiveness_score > 0

        # Same action without an explicit historical-memory citation must not
        # receive a reuse reward merely because the action name matches.
        uncited_target = str(uuid4())
        await service.retrieve(
            "nginx inactive port 86 tcp unreachable",
            service_scope="nginx",
            retrieval_mode="SIMILAR_INCIDENT",
            limit=10,
            successful_only=False,
            target_incident_id=uncited_target,
            record_retrieval=True,
        )
        before_success = int(refreshed.successful_reuse_count or 0)
        await service.record_feedback(
            uncited_target,
            execution_request={"action": "start_service"},
            verification_result={"status": "success"},
            cited_memory_ids=[],
        )
        await db.refresh(refreshed)
        assert int(refreshed.successful_reuse_count or 0) == before_success
        uncited_events = (
            await db.execute(
                select(MemoryReuseEvent).where(
                    MemoryReuseEvent.target_incident_id == uncited_target
                )
            )
        ).scalars().all()
        assert uncited_events
        assert not any(event.influenced_plan for event in uncited_events)

        stale_incident = str(uuid4())
        stale_id = await service.add_episode(
            OperationalMemoryBuilder.build(
                _state(stale_incident, success=True)
            )
        )
        stale_row = await db.get(MemoryEntry, stale_id)
        assert stale_row is not None
        stale_row.created_at = datetime.now(timezone.utc) - timedelta(
            days=settings.MEMORY_STALE_AFTER_DAYS + 1
        )
        stale_row.last_validated_at = None
        await db.commit()

        stale_count = await service.mark_stale_entries(limit=100)
        assert stale_count >= 1
        await db.refresh(stale_row)
        assert stale_row.lifecycle_status == "stale"

        after_stale = await service.retrieve(
            "nginx inactive port 86 tcp unreachable",
            service_scope="nginx",
            retrieval_mode="SIMILAR_INCIDENT",
            limit=20,
            successful_only=False,
        )
        assert str(stale_id) not in {item["id"] for item in after_stale}

        assert await service.mark_validated(stale_id) is True
        await db.refresh(stale_row)
        assert stale_row.lifecycle_status == "active"
        assert stale_row.last_validated_at is not None
