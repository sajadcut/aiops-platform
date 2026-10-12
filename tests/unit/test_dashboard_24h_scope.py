"""Dashboard incident visibility is a rolling 24h view, not incident deletion."""

from pathlib import Path

import pytest

import apps.api.dashboard_incidents as dashboard_incidents


class _Rows:
    def mappings(self):
        return self

    def all(self):
        return []


class _Session:
    def __init__(self):
        self.statements = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, _type, _value, _traceback):
        return False

    async def execute(self, statement, params=None):
        self.statements.append((statement.text, params))
        return _Rows()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("scope", "expected_predicate"),
    [
        ("recent", "i.created_at >= CURRENT_TIMESTAMP - INTERVAL '24 hours'"),
        ("archived", "i.created_at < CURRENT_TIMESTAMP - INTERVAL '24 hours'"),
    ],
)
async def test_incident_api_scopes_are_parameterized_and_non_destructive(monkeypatch, scope, expected_predicate):
    session = _Session()
    monkeypatch.setattr(dashboard_incidents, "AsyncSessionLocal", lambda: session)

    response = await dashboard_incidents.dashboard_incidents(limit=100, scope=scope, _identity={})

    assert response["items"] == []
    assert response["scope"] == scope
    assert response["window_hours"] == 24
    assert len(session.statements) == 1
    query, binds = session.statements[0]
    assert expected_predicate in query
    assert ":scope = 'recent'" in query and ":scope = 'archived'" in query
    assert binds == {"limit": 100, "scope": scope}
    assert "DELETE FROM" not in query.upper()


@pytest.mark.asyncio
async def test_service_health_is_limited_to_recent_incidents(monkeypatch):
    session = _Session()
    monkeypatch.setattr(dashboard_incidents, "AsyncSessionLocal", lambda: session)

    response = await dashboard_incidents.dashboard_services(limit=100, _identity={})

    assert response["items"] == []
    assert len(session.statements) == 1
    query, binds = session.statements[0]
    assert "FROM incidents i" in query
    assert "WHERE i.created_at >= CURRENT_TIMESTAMP - INTERVAL '24 hours'" in query
    assert binds == {"limit": 100}


def test_summary_incident_kpis_use_the_same_recent_window():
    source = Path("apps/api/dashboard.py").read_text(encoding="utf-8")
    for metric in ("incidents_total", "incidents_active", "incidents_critical"):
        line = next(line for line in source.splitlines() if f"AS {metric}," in line)
        assert "created_at >= CURRENT_TIMESTAMP - INTERVAL '24 hours'" in line


def test_archive_is_explicit_and_cannot_pollute_live_attention_or_kpis():
    html = Path("dashboards/index.html").read_text(encoding="utf-8")
    js = Path("dashboards/control-center.js").read_text(encoding="utf-8")
    assert 'id="incidentPeriod"' in html
    assert 'value="recent" selected' in html
    assert 'value="archived"' in html
    assert "archived ? S.archivedIncidents : S.incidents" in html
    assert "scope=archived" in js
    assert "S.archivedIncidents = result.items || []" in js
    assert "S.incidents = incidents.items || []" in js
    assert "const attention = S.incidents.filter" in js
    assert "setInterval(loadAll, 60000)" in js
