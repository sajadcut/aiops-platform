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


pytestmark = [
    pytest.mark.skipif(
        os.getenv("RUN_DB_MEMORY_V2_TEST") != "1",
        reason="requires PostgreSQL/pgvector database acceptance environment",
    ),
    pytest.mark.asyncio(loop_scope="module"),
]


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


async def test_memory_v2_reembeds_stale_embedding_contract():
    incident_id = str(uuid4())

    async with AsyncSessionLocal() as db:
        service = OperationalMemoryService(db)
        episode = OperationalMemoryBuilder.build(
            _state(incident_id, success=True)
        )
        memory_id = await service.add_episode(episode)
        row = await db.get(MemoryEntry, memory_id)
        assert row is not None
        assert row.embedding is not None

        row.embedding_model = "obsolete-embedding-model"
        row.embedding_document_version = "obsolete-document-version"
        row.embedding_document = "legacy embedding text that must be rebuilt"
        row.embedding_text_hash = "obsolete-hash"
        await db.commit()

        stats_before = await service.stats()
        assert stats_before["embedding_contract_mismatch"] >= 1
        backlog_before = int(stats_before["embedding_backlog"])

        lexical_only = await service.retrieve(
            "nginx inactive port 86 unavailable",
            service_scope="nginx",
            environment="test",
            retrieval_mode="SIMILAR_INCIDENT",
            limit=10,
            successful_only=False,
        )
        match = next(item for item in lexical_only if item["id"] == str(memory_id))
        assert match["lexical_score"] > 0
        assert match["vector_similarity"] == 0.0

        result = await service.backfill_embeddings(limit=100)
        assert result["selected"] >= 1

        await db.refresh(row)
        assert row.embedding_status == "ready"
        assert row.embedding_provider == settings.EMBEDDING_PROVIDER
        assert row.embedding_model == settings.EMBEDDING_MODEL
        assert row.embedding_dimension == settings.EMBEDDING_DIMENSION
        assert row.embedding_document_version == OperationalMemoryBuilder.EMBEDDING_DOCUMENT_VERSION
        assert row.embedding_document != "legacy embedding text that must be rebuilt"
        assert row.embedding_text_hash not in {None, "", "obsolete-hash"}
        assert row.embedding is not None

        stats_after = await service.stats()
        assert int(stats_after["embedding_backlog"]) < backlog_before


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

        self_excluded = await service.retrieve(
            "nginx inactive port 86 tcp unreachable",
            service_scope="nginx",
            environment="test",
            retrieval_mode="SIMILAR_INCIDENT",
            limit=10,
            successful_only=False,
            target_incident_id=successful_incident,
            record_retrieval=False,
        )
        assert str(success_id) not in {item["id"] for item in self_excluded}

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
        before_cited = int(success_row.cited_count or 0)
        before_reuse = int(success_row.reuse_count or 0)
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
        assert int(refreshed.cited_count or 0) == before_cited + 1
        assert int(refreshed.reuse_count or 0) == before_reuse + 1
        assert refreshed.effectiveness_score > 0

        # Citation with a different current action is still a citation, but it
        # must not be counted as action reuse or change effectiveness.
        mismatch_target = str(uuid4())
        await service.retrieve(
            "nginx inactive port 86 tcp unreachable",
            service_scope="nginx",
            retrieval_mode="SIMILAR_INCIDENT",
            limit=10,
            successful_only=False,
            target_incident_id=mismatch_target,
            record_retrieval=True,
        )
        cited_before_mismatch = int(refreshed.cited_count or 0)
        reuse_before_mismatch = int(refreshed.reuse_count or 0)
        success_before_mismatch = int(refreshed.successful_reuse_count or 0)
        effectiveness_before_mismatch = float(refreshed.effectiveness_score or 0.0)
        await service.record_feedback(
            mismatch_target,
            execution_request={"action": "restart_service"},
            verification_result={"status": "success"},
            cited_memory_ids=[str(success_id)],
        )
        await db.refresh(refreshed)
        assert int(refreshed.cited_count or 0) == cited_before_mismatch + 1
        assert int(refreshed.reuse_count or 0) == reuse_before_mismatch
        assert int(refreshed.successful_reuse_count or 0) == success_before_mismatch
        assert float(refreshed.effectiveness_score or 0.0) == effectiveness_before_mismatch

        mismatch_events = (
            await db.execute(
                select(MemoryReuseEvent).where(
                    MemoryReuseEvent.target_incident_id == mismatch_target
                )
            )
        ).scalars().all()
        assert mismatch_events
        assert any(event.was_cited_by_agent for event in mismatch_events)
        assert not any(event.influenced_plan for event in mismatch_events)

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


async def test_memory_v2_incident_learning_a_b_c_acceptance():
    """Prove A -> Memory -> B governed reuse feedback and C negative learning."""
    incident_a = str(uuid4())
    incident_b = str(uuid4())
    incident_c = str(uuid4())

    async with AsyncSessionLocal() as db:
        service = OperationalMemoryService(db)

        # Incident A: verified successful recovery becomes durable experience.
        memory_a = await service.add_episode(
            OperationalMemoryBuilder.build(_state(incident_a, success=True))
        )
        row_a = await db.get(MemoryEntry, memory_a)
        assert row_a is not None
        assert row_a.memory_outcome_class == "successful_recovery"
        assert row_a.verification_result["status"] == "success"

        # Incident B: the similar historical episode is retrieved as auxiliary
        # context, explicitly cited, matched to the governed action, and rewarded
        # only after fresh successful verification.
        retrieved_b = await service.retrieve(
            "nginx inactive port 86 unavailable tcp unreachable",
            service_scope="nginx",
            environment="test",
            retrieval_mode="REMEDIATION_EXPERIENCE",
            limit=10,
            successful_only=False,
            target_incident_id=incident_b,
            record_retrieval=True,
        )
        match_a = next(item for item in retrieved_b if item["id"] == str(memory_a))
        assert match_a["safe_as_evidence"] is False
        assert match_a["requires_current_validation"] is True

        before_reuse = int(row_a.reuse_count or 0)
        before_success = int(row_a.successful_reuse_count or 0)
        await service.record_feedback(
            incident_b,
            execution_request={"action": "start_service"},
            verification_result={"status": "success"},
            cited_memory_ids=[str(memory_a)],
        )
        await db.refresh(row_a)
        assert int(row_a.reuse_count or 0) == before_reuse + 1
        assert int(row_a.successful_reuse_count or 0) == before_success + 1

        reuse_events_b = (
            await db.execute(
                select(MemoryReuseEvent).where(
                    MemoryReuseEvent.target_incident_id == incident_b
                )
            )
        ).scalars().all()
        assert any(
            event.was_cited_by_agent
            and event.action_executed
            and event.influenced_plan
            and event.verification_outcome == "success"
            for event in reuse_events_b
        )

        # Incident C: a failed governed attempt is retained as negative
        # experience. It can warn later analysis, but is never safe Evidence.
        memory_c = await service.add_episode(
            OperationalMemoryBuilder.build(_state(incident_c, success=False))
        )
        row_c = await db.get(MemoryEntry, memory_c)
        assert row_c is not None
        assert row_c.memory_outcome_class == "failed_recovery"
        assert row_c.verification_result["status"] == "failed"

        retrieved_c = await service.retrieve(
            "nginx inactive port 86 unavailable start service",
            service_scope="nginx",
            environment="test",
            retrieval_mode="REMEDIATION_EXPERIENCE",
            limit=20,
            successful_only=False,
            target_incident_id=str(uuid4()),
            record_retrieval=False,
        )
        negative = next(item for item in retrieved_c if item["id"] == str(memory_c))
        assert negative["memory_outcome_class"] == "failed_recovery"
        assert negative["safe_as_evidence"] is False
        assert negative["requires_current_validation"] is True
