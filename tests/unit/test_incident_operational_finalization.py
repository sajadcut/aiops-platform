from types import SimpleNamespace

import pytest

from apps.incident_service.repository import IncidentRepository
from domain.models import IncidentStatus


class FakeSession:
    def __init__(self, incident):
        self.incident = incident

    async def get(self, _model, _incident_id):
        return self.incident


@pytest.mark.asyncio
async def test_operational_outcome_resolves_only_verified_recovery():
    incident = SimpleNamespace(
        status=IncidentStatus.ANALYZING,
        context={},
    )
    repo = IncidentRepository(FakeSession(incident))

    status = await repo.record_operational_outcome(
        "11111111-1111-1111-1111-111111111111",
        source="direct_execution",
        action="start_service",
        target="10.100.6.199",
        approval_id="approval-1",
        execution_success=True,
        verified=True,
        verification={
            "status": "success",
            "required_objectives_met": True,
        },
        memory_id="memory-1",
    )

    assert status == "resolved"
    assert incident.status == IncidentStatus.RESOLVED
    latest = incident.context["latest_operational_outcome"]
    assert latest["verified"] is True
    assert latest["execution_success"] is True
    assert latest["memory_id"] == "memory-1"
    assert latest["recorded_at"]
    assert len(incident.context["operational_outcomes"]) == 1


@pytest.mark.asyncio
async def test_operational_outcome_escalates_failed_or_inconclusive_recovery():
    incident = SimpleNamespace(
        status=IncidentStatus.ANALYZING,
        context={},
    )
    repo = IncidentRepository(FakeSession(incident))

    status = await repo.record_operational_outcome(
        "11111111-1111-1111-1111-111111111111",
        source="remediation_execution",
        action="restart_service",
        target="10.100.6.199",
        approval_id="approval-2",
        execution_success=True,
        verified=False,
        verification={
            "status": "partial",
            "required_objectives_met": False,
        },
        memory_id="memory-2",
    )

    assert status == "escalated"
    assert incident.status == IncidentStatus.ESCALATED
    assert (
        incident.context["latest_operational_outcome"]["verification"]["status"]
        == "partial"
    )


@pytest.mark.asyncio
async def test_operational_outcome_preserves_authoritative_source_recovery():
    incident = SimpleNamespace(
        status=IncidentStatus.RESOLVED,
        context={
            "source_recovery": {
                "incident_resolved": True,
                "source": "zabbix",
            }
        },
    )
    repo = IncidentRepository(FakeSession(incident))

    status = await repo.record_operational_outcome(
        "11111111-1111-1111-1111-111111111111",
        source="manual_verification",
        action="start_service",
        target="10.100.6.199",
        approval_id="approval-3",
        execution_success=None,
        verified=False,
        verification={"status": "failed"},
        memory_id=None,
    )

    assert status == "resolved"
    assert incident.status == IncidentStatus.RESOLVED
    assert incident.context["source_recovery"]["incident_resolved"] is True


@pytest.mark.asyncio
async def test_repeated_same_operational_outcome_updates_bounded_identity_not_duplicate():
    incident = SimpleNamespace(
        status=IncidentStatus.ANALYZING,
        context={},
    )
    repo = IncidentRepository(FakeSession(incident))

    kwargs = dict(
        source="manual_verification",
        action="start_service",
        target="10.100.6.199",
        approval_id="approval-4",
        execution_success=True,
        verified=True,
        verification={"status": "success"},
    )
    await repo.record_operational_outcome(
        "11111111-1111-1111-1111-111111111111",
        **kwargs,
        memory_id="memory-old",
    )
    await repo.record_operational_outcome(
        "11111111-1111-1111-1111-111111111111",
        **kwargs,
        memory_id="memory-new",
    )

    assert len(incident.context["operational_outcomes"]) == 1
    assert (
        incident.context["latest_operational_outcome"]["memory_id"]
        == "memory-new"
    )
