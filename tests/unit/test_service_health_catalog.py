"""Acceptance tests for service-health catalog and honest operational facts."""
from types import SimpleNamespace
from uuid import UUID

import pytest
from pydantic import ValidationError

from apps.api import service_catalog as catalog
from apps.decision_brief import operator_presentation_context


def test_profile_rejects_untrusted_uri_paths_and_unknown_fields():
    model = catalog.ServiceHealthProfile(
        expected_port=8080, health_path="/health/ready", owner="team-a",
        dependencies=["postgres"])
    assert model.health_scheme == "http"
    for path in ["//metadata/", "/../../admin", "http://evil.local/",
                 "/health?token=x", "/health#fragment", "/health path"]:
        with pytest.raises(ValidationError):
            catalog.ServiceHealthProfile(health_path=path)
    with pytest.raises(ValidationError):
        catalog.ServiceHealthProfile(expected_port=0)
    with pytest.raises(ValidationError):
        catalog.ServiceHealthProfile(credentials="secret")


def test_http_target_restricted_to_private_incident_ipv4():
    assert catalog._safe_health_target("10.248.16.82")
    for value in ["8.8.8.8", "127.0.0.1", "::1", "localhost",
                  "169.254.169.254", "0.0.0.0"]:
        assert not catalog._safe_health_target(value)


def test_http_state_requires_matching_service_and_target():
    row = {"event_type": "service_http_health_rechecked",
           "created_at": "2026-10-14T09:30:00Z",
           "metadata": {"service": "gfpapi", "target": "10.248.16.82",
                        "status": "healthy", "http_code": 204}}
    assert catalog._health_result([row], "gfpapi", "10.248.16.82")["status"] == "healthy"
    assert catalog._health_result([row], "nginx", "10.248.16.82")["status"] == "not_checked"


def test_only_direct_matching_vm_evidence_enters_operational_facts():
    incident = {"service": "gfpapi", "context": {"trigger_signal": {
        "payload": {"platform": "vm", "target_ip": "10.248.16.82"}}}}
    def row(source, diagnostic, name, state, date):
        return {"source": source, "created_at": date,
                "raw_data": {"diagnostic": diagnostic, "service": name,
                             "target": "10.248.16.82", "success": True,
                             "active_state": state, "sub_state": "running"}}
    evidence = [
        row("zabbix", "service_status", "gfpapi", "failed", "2026-10-14T09:28:00Z"),
        row("vm_mcp", "service_status", "gfpapi", "active", "2026-10-14T09:27:00Z"),
        row("vm_mcp", "service_status", "nginx", "failed", "2026-10-14T09:29:00Z"),
        {"source": "vm_mcp", "created_at": "2026-10-14T09:27:00Z",
         "raw_data": {"diagnostic": "dotnet_config_syntax", "service": "gfpapi",
                      "target": "10.248.16.82", "success": True, "syntax_valid": True}},
    ]
    status = operator_presentation_context(
        incident, {"evaluation": {"approved_for_decision": False},
                   "terminal_reason": "insufficient_evidence"},
        evidence, {"observed_state": {"target": "10.248.16.82"}},
    )
    assert status["platform"] == "vm_systemd"
    assert status["action_disposition"] == "blocked_by_evaluator"
    assert status["no_action_authorized"] is True
    assert status["observations"]["service_status"]["values"]["active_state"] == "active"
    assert status["observations"]["dotnet_config_syntax"]["values"]["syntax_valid"] is True


@pytest.mark.asyncio
async def test_recheck_http_is_explicit_with_no_proxy_redirect_or_credentials(monkeypatch):
    events = []
    class FakeDb:
        async def __aenter__(self): return self
        async def __aexit__(self, *args): return False
    class FakeResponse:
        status_code = 204
    class FakeClient:
        def __init__(self, **opts):
            assert opts["follow_redirects"] is False
            assert opts["trust_env"] is False
        async def __aenter__(self): return self
        async def __aexit__(self, *args): return False
        async def get(self, url):
            events.append(("get", url))
            return FakeResponse()
    class FakeAudit:
        def __init__(self, db): pass
        async def append(self, event):
            events.append(("audit", event))
    async def scope(db, incident_id):
        return SimpleNamespace(service="gfpapi"), "10.248.16.82", {}
    async def profile(db, service, target):
        return {"profile": {"health_scheme": "http", "expected_port": 8080,
                            "health_path": "/health"}}
    monkeypatch.setattr(catalog, "AsyncSessionLocal", FakeDb)
    monkeypatch.setattr(catalog, "_bound_scope", scope)
    monkeypatch.setattr(catalog, "_profile_row", profile)
    monkeypatch.setattr(catalog, "PostgreSQLAuditStore", FakeAudit)
    monkeypatch.setattr(catalog, "verified_async_client", FakeClient)
    result = await catalog.recheck_http_health(
        UUID("11111111-1111-4111-8111-111111111111"),
        identity=SimpleNamespace(subject="sre"))
    assert result["status"] == "healthy"
    assert events[0] == ("get", "http://10.248.16.82:8080/health")
    assert events[1][1]["action"] == "http_health_read"


@pytest.mark.asyncio
async def test_invalid_target_aborts_before_probe_or_lookup(monkeypatch):
    class FakeDb:
        async def __aenter__(self): return self
        async def __aexit__(self, *args): return False
    async def scope(db, incident_id):
        return SimpleNamespace(service="gfpapi"), "169.254.169.254", {}
    async def impossible(*args, **kwargs):
        raise AssertionError("unsafe destination must not be fetched")
    monkeypatch.setattr(catalog, "AsyncSessionLocal", FakeDb)
    monkeypatch.setattr(catalog, "_bound_scope", scope)
    monkeypatch.setattr(catalog, "_profile_row", impossible)
    from fastapi import HTTPException
    with pytest.raises(HTTPException) as err:
        await catalog.recheck_http_health(
            UUID("11111111-1111-4111-8111-111111111111"),
            identity=SimpleNamespace(subject="operator"))
    assert err.value.status_code == 409
