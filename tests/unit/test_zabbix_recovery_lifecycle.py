from __future__ import annotations

from uuid import UUID

import pytest

from apps.approval_service.postgres import PostgreSQLApprovalStore
from apps.incident_service.repository import IncidentRepository
from apps.signal_gateway import zabbix_lifecycle
from apps.signal_gateway.zabbix_lifecycle import (
    _record_source_recovery,
    classify_zabbix_lifecycle,
    ingest_zabbix_payload,
)
from domain.models import Incident, IncidentStatus


INCIDENT_ID = "11111111-1111-1111-1111-111111111111"


def test_zabbix_operational_value_zero_is_not_misclassified_as_recovery():
    identity = classify_zabbix_lifecycle(
        {
            "eventid": "p-1",
            "name": "NeoBanking-Checkport 8800 is down",
            "value": "0",
        }
    )
    assert identity == {
        "state": "problem",
        "source_id": "p-1",
        "problem_event_id": "p-1",
        "recovery_event_id": None,
    }


def test_zabbix_recovery_event_binds_recovery_id_to_original_problem_id():
    identity = classify_zabbix_lifecycle(
        {
            "eventid": "p-1",
            "recovery_eventid": "r-1",
            "event_value": "0",
            "recovery_status": "RESOLVED",
        }
    )
    assert identity["state"] == "recovery"
    assert identity["problem_event_id"] == "p-1"
    assert identity["recovery_event_id"] == "r-1"
    assert identity["source_id"] == "r-1"


def test_explicit_recovery_without_recovery_macro_requires_problem_event_id():
    identity = classify_zabbix_lifecycle(
        {
            "eventid": "r-2",
            "problem_eventid": "p-2",
            "event_state": "recovery",
        }
    )
    assert identity["state"] == "recovery"
    assert identity["problem_event_id"] == "p-2"
    assert identity["recovery_event_id"] == "r-2"


class _IncidentSession:
    def __init__(self, incident: Incident):
        self.incident = incident

    async def get(self, model, incident_id):
        assert model is Incident
        assert incident_id == self.incident.id
        return self.incident


@pytest.mark.asyncio
async def test_single_source_zabbix_recovery_resolves_incident():
    incident = Incident(
        id=UUID(INCIDENT_ID),
        source="zabbix",
        severity="medium",
        service="neobanking",
        status=IncidentStatus.ANALYZING,
        summary="port down",
        context={"related_signals": []},
    )
    outcome = await _record_source_recovery(
        _IncidentSession(incident),
        incident_id=INCIDENT_ID,
        problem_event_id="p-1",
        recovery_event_id="r-1",
        payload={"name": "RECOVERY", "recovery_timestamp": "1757930000"},
    )
    assert outcome["incident_resolved"] is True
    assert outcome["incident_status"] == "resolved"
    assert incident.status == IncidentStatus.RESOLVED
    assert incident.context["source_recovery"]["problem_event_id"] == "p-1"


@pytest.mark.asyncio
async def test_zabbix_recovery_with_other_correlated_signal_requires_cross_source_verification():
    incident = Incident(
        id=UUID(INCIDENT_ID),
        source="zabbix",
        severity="medium",
        service="neobanking",
        status=IncidentStatus.ANALYZING,
        summary="port down",
        context={
            "related_signals": [
                {"source": "prometheus", "source_id": "prom-1", "signal_type": "TargetDown"}
            ]
        },
    )
    outcome = await _record_source_recovery(
        _IncidentSession(incident),
        incident_id=INCIDENT_ID,
        problem_event_id="p-1",
        recovery_event_id="r-1",
        payload={"name": "RECOVERY"},
    )
    assert outcome["incident_resolved"] is False
    assert outcome["requires_cross_source_verification"] is True
    assert incident.status == IncidentStatus.ANALYZING


@pytest.mark.asyncio
async def test_late_workflow_write_cannot_reopen_source_recovered_incident():
    incident = Incident(
        id=UUID(INCIDENT_ID),
        source="zabbix",
        severity="medium",
        service="neobanking",
        status=IncidentStatus.RESOLVED,
        summary="port down",
        context={
            "source_recovery": {
                "problem_event_id": "p-1",
                "recovery_event_id": "r-1",
                "incident_resolved": True,
            },
            "source_recoveries": [{"problem_event_id": "p-1", "recovery_event_id": "r-1"}],
        },
    )
    session = _IncidentSession(incident)
    repository = IncidentRepository(session)
    await repository.upsert_incident(
        INCIDENT_ID,
        source="zabbix",
        service="neobanking",
        severity="medium",
        summary="stale analysis result",
        status="analyzing",
        context={"incident": {"source": "zabbix"}},
    )
    assert incident.status == IncidentStatus.RESOLVED
    assert incident.context["source_recovery"]["recovery_event_id"] == "r-1"


class _ApprovalExecuteResult:
    pass


class _ApprovalSession:
    def __init__(self):
        self.params = None
        self.commits = 0

    async def execute(self, statement, params=None):
        self.params = dict(params or {})
        return _ApprovalExecuteResult()

    async def commit(self):
        self.commits += 1


@pytest.mark.asyncio
async def test_late_approval_is_persisted_rejected_after_source_recovery(monkeypatch):
    session = _ApprovalSession()
    store = PostgreSQLApprovalStore(session)

    async def recovered(_incident_id):
        return True

    async def no_record(_approval_id):
        return None

    monkeypatch.setattr(store, "_incident_source_recovered", recovered)
    monkeypatch.setattr(store, "get", no_record)

    result = await store.save(
        {
            "approval_id": "a-1",
            "incident_id": INCIDENT_ID,
            "action": "restart_service",
            "risk_level": "high",
            "approver": "SRE-OnCall",
            "status": "pending",
            "metadata": {},
            "created_at": "2026-09-15T12:00:00+00:00",
            "approved_at": None,
            "rejected_at": None,
        }
    )
    assert session.params["status"] == "rejected"
    assert "cancelled_due_to_source_recovery" in session.params["metadata"]
    assert result["status"] == "rejected"


@pytest.mark.asyncio
async def test_recovery_ingest_updates_existing_incident_and_never_creates_new_one(monkeypatch):
    calls = {"evidence": [], "saved": []}

    class FakeIncidentRepository:
        def __init__(self, session):
            pass

        async def find_incident_by_evidence_reference(self, *, source, reference):
            if reference == "r-1":
                return None
            if reference == "p-1":
                return INCIDENT_ID
            return None

        async def acquire_correlation_lock(self, fingerprint):
            assert fingerprint == "zabbix-recovery:p-1"

        async def add_evidence(self, incident_id, evidence):
            calls["evidence"].extend(evidence)

        async def commit(self):
            return None

    class FakeCheckpointStore:
        def __init__(self, session):
            pass

        async def load(self, incident_id):
            return {"state": {"context": {"trigger_evidence": [], "evidence": []}}, "status": "paused"}

        async def save(self, incident_id, state, status="paused"):
            calls["saved"].append((incident_id, state, status))
            return {"status": status}

    class FakeApprovalStore:
        def __init__(self, session):
            pass

        async def cancel_unconsumed_for_incident(self, incident_id, *, reason, metadata_patch=None):
            assert incident_id == INCIDENT_ID
            assert reason == "zabbix_source_recovery"
            return ["a-1"]

    async def fake_record_source_recovery(*args, **kwargs):
        return {
            "incident_status": "resolved",
            "incident_resolved": True,
            "requires_cross_source_verification": False,
            "correlated_signal_count": 0,
        }

    async def fake_audit(*args, **kwargs):
        return None

    monkeypatch.setattr(zabbix_lifecycle, "IncidentRepository", FakeIncidentRepository)
    monkeypatch.setattr(zabbix_lifecycle, "WorkflowCheckpointStore", FakeCheckpointStore)
    monkeypatch.setattr(zabbix_lifecycle, "PostgreSQLApprovalStore", FakeApprovalStore)
    monkeypatch.setattr(zabbix_lifecycle, "_record_source_recovery", fake_record_source_recovery)
    monkeypatch.setattr(zabbix_lifecycle, "_audit_recovery", fake_audit)

    state = await ingest_zabbix_payload(
        object(),
        {
            "eventid": "p-1",
            "recovery_eventid": "r-1",
            "event_value": "0",
            "name": "NeoBanking-Checkport 8800 is down",
        },
    )
    assert state["incident_id"] == INCIDENT_ID
    assert state["signal_state"] == "recovery"
    assert state["recovery_of_source_id"] == "p-1"
    assert state["approval_cancellations"] == ["a-1"]
    assert state["verification_result"]["status"] == "success"
    assert calls["evidence"][0]["reference"] == "r-1"
    assert calls["saved"][0][2] == "completed"
