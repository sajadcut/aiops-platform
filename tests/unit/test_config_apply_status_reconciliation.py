"""Post-approval recovery must refresh the Incident Room without fake health."""

from datetime import datetime, timezone
from types import SimpleNamespace
from uuid import UUID

import pytest

from apps.incident_service.service_recovery_reconciliation import (
    _bound_systemd_observation, record_post_config_service_status,
)


TARGET = "192.0.2.18"
SERVICE = "nginx"


def _status(active="active", sub="running", **changes):
    return {
        "success": True, "target": TARGET, "service": SERVICE,
        "load_state": "loaded", "active_state": active, "sub_state": sub,
        "restart_count": 31, **changes,
    }


def test_post_apply_evidence_accepts_only_matching_bounded_systemd_facts():
    result = _bound_systemd_observation({
        **_status(), "systemctl_status": "SECRET CONTENT",
        "configuration": "DO NOT PERSIST",
    }, target=TARGET, service=SERVICE)
    assert result == {
        "success": True, "target": TARGET, "service": SERVICE,
        "load_state": "loaded", "active_state": "active", "sub_state": "running",
        "restart_count": 31,
    }
    assert _bound_systemd_observation(
        _status(target="192.0.2.200"), target=TARGET, service=SERVICE,
    ) is None
    assert _bound_systemd_observation(
        _status(service="haproxy"), target=TARGET, service=SERVICE,
    ) is None


@pytest.mark.asyncio
async def test_post_apply_persists_live_observation_not_fabricated_monitor_recovery():
    import json

    class Db:
        def __init__(self):
            self.calls = []
        async def execute(self, query, params):
            self.calls.append(params)
    db = Db()
    stable = await record_post_config_service_status(
        db, incident_id=str(UUID(int=1)), target=TARGET, service=SERVICE,
        actor="sre", first=_status(), second=_status(),
        vendor_syntax_ok=True,
    )
    assert stable is True and len(db.calls) == 1
    meta = json.loads(db.calls[0]["metadata"])
    assert meta["stable_pair"] is True
    assert meta["monitor_recovery_confirmed"] is False
    assert db.calls[0]["event_type"] == "incident_config_apply_service_rechecked"
    assert "systemctl_status" not in meta["observation"]

    db.calls.clear()
    stable = await record_post_config_service_status(
        db, incident_id=str(UUID(int=1)), target=TARGET, service=SERVICE,
        actor="sre", first=_status(), second=_status(),
        vendor_syntax_ok=False,
    )
    assert stable is False
    assert json.loads(db.calls[0]["metadata"])["stable_pair"] is False


def test_post_apply_stable_pair_supersedes_old_crash_loop_in_header():
    from apps.api.incident_chat import _observed_status

    def sample(when, active, sub, count):
        return {
            "source": "vm_mcp", "created_at": when, "reference": "old-event",
            "raw_data": {
                "diagnostic": "service_status", **_status(
                    active=active, sub=sub, restart_count=count,
                ),
            },
        }

    evidence = [
        sample("2026-10-16T14:00:00Z", "activating", "auto-restart", 30),
        sample("2026-10-16T14:01:00Z", "active", "running", 31),
    ]
    latest = {
        "event_type": "incident_config_apply_service_rechecked",
        "status": "success", "event_id": "approved-start",
        "created_at": "2026-10-16T14:02:00Z",
        "metadata": {"observation": _status(), "stable_pair": True},
    }
    card = _observed_status(SERVICE, TARGET, evidence, [latest])
    assert card["status"] == "running"
    assert card["source"] == "vm_mcp_post_config"
    assert "_post_repair_stable" not in card
    without_second_check = {
        **latest, "metadata": {**latest["metadata"], "stable_pair": False},
    }
    assert _observed_status(SERVICE, TARGET, evidence, [without_second_check])["status"] == "unstable"

    # A *new* crash after recovery is not hidden by the old repaired epoch.
    newer = sample("2026-10-16T14:03:00Z", "activating", "auto-restart", 32)
    status = _observed_status(SERVICE, TARGET, evidence + [newer], [latest])
    assert status["status"] == "unstable"


@pytest.mark.asyncio
async def test_reconcile_after_config_closes_only_matching_service_down_incident(monkeypatch):
    import apps.incident_service.service_recovery_reconciliation as module
    from domain.models import IncidentStatus
    import database
    import integrations.vm.mcp_client as mcp

    incident = SimpleNamespace(
        id=UUID(int=1), source="zabbix", summary="nginx Service Down",
        service=SERVICE, context={"related_signals": []},
        status=IncidentStatus.OPEN,
    )

    class QueryResult:
        def scalar_one_or_none(self):
            return incident
        def scalars(self):
            return self
        def all(self):
            return []
    class Db:
        def __init__(self):
            self.sql = []
            self.commits = 0
        async def __aenter__(self):
            return self
        async def __aexit__(self, *_):
            return None
        async def execute(self, query, params=None):
            self.sql.append(str(query))
            return QueryResult()
        async def flush(self):
            return None
        async def commit(self):
            self.commits += 1
    db = Db()
    class FakeClient:
        def __init__(self):
            self.calls = 0
        async def service_status(self, target, service):
            self.calls += 1
            return _status()
        async def config_validate(self, target, service):
            return {"success": True, "supported": True, "valid": True}
    async def no_wait(_):
        return None
    monkeypatch.setattr(database, "AsyncSessionLocal", lambda: db)
    monkeypatch.setattr(mcp, "VMEdgeMCPClient", FakeClient)
    monkeypatch.setattr(module.asyncio, "sleep", no_wait)

    decision = await module.reconcile_after_applied_config(
        incident_id=str(incident.id), target=TARGET, service=SERVICE, actor="sre",
    )
    assert decision == "resolved_independent_vm_verified"
    assert incident.status == IncidentStatus.RESOLVED
    assert any("incident_config_apply_service_rechecked" in stmt for stmt in []) is False
    assert len([q for q in db.sql if "INSERT INTO audit_events" in q]) == 2
    assert db.commits == 1
    assert incident.context["independent_recovery"]["monitor_recovered"] is False


def test_incident_room_binds_header_to_live_lifecycle_and_post_config_status():
    from pathlib import Path
    source = (Path(__file__).resolve().parents[2]
              / "dashboards" / "incident-command-room.js").read_text(encoding="utf-8")
    assert "state.lifecycle?.incident_status||i.status" in source
    assert "o.source==='vm_mcp_post_config'" in source
    assert "value.incident_resolved===true" in source
