"""Regression: dependency diagnostics must be visible, structured and read-only."""
from datetime import datetime, timezone

from apps.decision_brief import _mcp
from apps.incident_investigation_report import dependency_checks


def test_dependency_probe_facts_survive_brief_and_ledger_without_raw_config():
    rows = [{
        "id": "ev-redis", "source": "vm_mcp",
        "created_at": "2026-10-19T17:15:12Z",
        "raw_data": {
            "mcp_server": "vm_mcp", "tool_name": "dependency_investigation",
            "success": True, "checks_executed": 2,
            "dependencies": [
                {
                    "kind": "redis", "host": "cache.internal", "port": 6379,
                    "config_file": "/srv/app/appsettings.json",
                    "config_key": "Redis.Endpoints.Host",
                    "probe_status": "tcp_reachable", "tcp_reachable": True,
                    "protocol_status": "client_not_installed",
                    "password": "DO_NOT_EXPOSE",
                }, {
                    "kind": "https", "host": "api.internal", "port": 8443,
                    "probe_status": "http_responded", "http_status": 503,
                },
            ],
        },
    }]
    evidence, _ = _mcp(rows, datetime(2026, 10, 19, 17, 16, tzinfo=timezone.utc))
    checks = dependency_checks({"mcp_evidence": evidence})
    assert checks["status"] == "recorded"
    assert checks["read_only"] is True
    assert checks["application_health_verified"] is False
    assert len(checks["items"]) == 2
    redis = checks["items"][0]
    assert redis["host"] == "cache.internal"
    assert redis["config_key"] == "Redis.Endpoints.Host"
    assert redis["tcp_reachable"] is True
    assert redis["protocol_status"] == "client_not_installed"
    assert redis["evidence_ref"] == "ev-redis"
    assert checks["items"][1]["http_status"] == 503
    assert "DO_NOT_EXPOSE" not in repr(checks)
    assert "password" not in repr(checks)


def test_no_dependency_check_is_not_misrepresented_as_healthy():
    absent = dependency_checks({"mcp_evidence": []})
    assert absent["status"] == "not_recorded"
    assert absent["items"] == []
    assert absent["application_health_verified"] is False
    incomplete = dependency_checks({"mcp_evidence": [{
        "tool": "dependency_investigation", "status": "success",
        "finding": "checks_executed=4",
    }]})
    assert incomplete["status"] == "details_not_recorded"


def test_incident_room_contains_visible_individual_probe_report():
    from pathlib import Path
    html = Path("dashboards/incident-command-room.html").read_text(encoding="utf-8")
    js = Path("dashboards/incident-command-room.js").read_text(encoding="utf-8")
    assert 'id="ic-dependency-checks"' in html
    assert 'id="ic-dependency-checks-body"' in html
    assert "renderDependencyChecks(state.report)" in js
    assert "protocol_status" in js
    assert "tcp_reachable" in js
