import json

import pytest

from agents.recovery import RecoveryAgent
from agents.shared.base import AgentInput
from integrations.llm.base import LLMAdapter, LLMResponse


class StaticLLM(LLMAdapter):
    @property
    def provider_name(self) -> str:
        return "static-test"

    async def generate(self, prompt, system_prompt=None, temperature=0.7, max_tokens=1000, **kwargs):
        return LLMResponse(content=json.dumps({
            "severity": "high",
            "health_status": "degraded",
            "findings": ["backup exists but recoverability must use verified restore evidence"],
            "affected_components": ["orders-db"],
            "probable_dependencies": [],
            "blast_radius": "orders service",
            "hypotheses": [],
            "missing_evidence": [],
            "handoff_agents": ["database"],
            "immediate_checks": ["Inspect restore validation history"],
            "confidence": 0.7,
        }), model="static-test")

    async def generate_with_messages(self, messages, temperature=0.7, max_tokens=1000, **kwargs):
        return await self.generate(messages[-1]["content"], temperature=temperature, max_tokens=max_tokens)


@pytest.mark.asyncio
async def test_recovery_exposes_verified_restore_point_and_data_loss_window():
    input_data = AgentInput(
        incident_id="rec-1",
        service_name="orders-db",
        evidence_summary="recovery readiness",
        context={
            "incident_start": "2026-09-16T10:00:00Z",
            "evidence": [
                {
                    "id": "backup-new",
                    "type": "log",
                    "source": "backup",
                    "message": "backup succeeded",
                    "raw_data": {"backup_time": "2026-09-16T09:30:00Z", "verified": False},
                },
                {
                    "id": "restore-old",
                    "type": "log",
                    "source": "backup",
                    "message": "restore test succeeded",
                    "raw_data": {"backup_time": "2026-09-16T08:00:00Z", "restore_verified": True},
                },
                {"id": "m1", "type": "metric", "source": "prometheus", "name": "replication_lag", "value": 0},
            ],
        },
    )

    output = await RecoveryAgent(StaticLLM()).analyze(input_data)
    details = output.analysis_details
    assert details["latest_backup"] == "2026-09-16T09:30:00+00:00"
    assert details["latest_verified_restore_point"] == "2026-09-16T08:00:00+00:00"
    assert details["potential_data_loss_window_seconds"] == 7200
    assert details["restore_validation_status"] == "verified_restore_point_available"
    assert details["human_decision_required"] is True
    assert details["recovery_sequence"] == ["storage", "database", "core_dependency", "application"]
    assert "Approval" in details["execution_policy"]


@pytest.mark.asyncio
async def test_recovery_marks_successful_unverified_backup_as_coverage_gap():
    input_data = AgentInput(
        incident_id="rec-2",
        service_name="orders-db",
        evidence_summary="backup succeeded",
        context={
            "evidence": [
                {
                    "id": "backup-only",
                    "type": "log",
                    "source": "backup",
                    "message": "backup succeeded",
                    "raw_data": {"backup_time": "2026-09-16T09:30:00Z", "verified": False},
                },
                {"id": "m1", "type": "metric", "source": "prometheus", "name": "backup_age_seconds", "value": 1800},
            ]
        },
    )

    output = await RecoveryAgent(StaticLLM()).analyze(input_data)
    details = output.analysis_details
    assert details["latest_backup"] is not None
    assert details["latest_verified_restore_point"] is None
    assert details["restore_validation_status"] == "restore_validation_missing"
    assert "verified usable restore point" in details["coverage_gaps"]
    assert details["potential_data_loss_window_seconds"] is None
