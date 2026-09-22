import os
from uuid import uuid4

import pytest
from sqlalchemy import select

from apps.memory_service import OperationalMemoryService
from apps.memory_service.builder import OperationalMemoryBuilder
from database import AsyncSessionLocal
from domain.models import MemoryEntry, MemoryReuseEvent


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

        success_row = await db.get(MemoryEntry, success_id)
        assert success_row is not None
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

        updated = await service.record_feedback(
            target_incident,
            execution_request={"action": "start_service"},
            verification_result={"status": "success"},
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
