"""Regression: do not claim Redis 6379 when application selected 6389."""
import base64
import json

import pytest

from integrations.vm.dependency_discovery import discover
from integrations.vm.dependency_investigation import investigate
from integrations.vm.redis_dependency import parse_redis_endpoints, check_redis_config
from apps.incident_alert_explanation import fallback_explanation


def test_nested_redis_port_6389_overrides_vendor_default():
    data = {"Redis": {"Port": 6389, "Endpoints": {"Host": "10.248.34.221"}}}
    endpoints = [d for d in discover(data) if d["kind"] == "redis"]
    assert len(endpoints) == 1
    assert endpoints[0]["host"] == "10.248.34.221"
    assert endpoints[0]["port"] == 6389
    assert endpoints[0]["port_inferred"] is False
    assert all(x["port"] != 6379 for x in endpoints)
    assert parse_redis_endpoints(data) == [{"host": "10.248.34.221", "port": 6389}]


def test_host_without_port_is_tentative_never_configured_endpoint():
    data = {"Redis": {"Endpoints": {"Host": "10.248.34.221"}}}
    rows = discover(data)
    assert rows[0]["port_inferred"] is True
    assert parse_redis_endpoints(data) == [
        {"host": "10.248.34.221", "port": None, "port_inferred": True}
    ]


@pytest.mark.asyncio
@pytest.mark.parametrize("data,expected_port,called", [
    ({"Redis": {"Endpoints": {"Host": "10.248.34.221"}, "Port": 6389}}, 6389, True),
    ({"Redis": {"Endpoints": {"Host": "10.248.34.221"}}}, 6379, False),
])
async def test_investigation_only_probes_proven_port(data, expected_port, called):
    encoded = base64.b64encode(json.dumps(data).encode()).decode()
    probes = []

    class Stub:
        def _validate_target(self, target): assert target == "vm"
        def _validate_service(self, service): assert service == "gfpapi"
        async def service_config_discovery(self, target, service):
            return {"success": True, "files": [{
                "path": "/data/gfp/gfpapi/appsettings.json", "verified_exists": True,
            }]}
        async def _run(self, target, command):
            return {"success": True, "stdout": encoded}
        async def tcp_check(self, target, host, port):
            probes.append((host, port))
            return {"success": True, "supported": True,
                    "reachable": port == 6379}

    result = await investigate(Stub(), "vm", "gfpapi")
    assert len(result["dependencies"]) == 1
    endpoint = result["dependencies"][0]
    assert endpoint["port"] == expected_port
    if called:
        assert probes == [("10.248.34.221", 6389)]
        assert endpoint["port_inferred"] is False
        assert endpoint["tcp_reachable"] is False
        assert result["investigation_status"] == "transport_failure_observed"
    else:
        assert probes == []
        assert endpoint["port_inferred"] is True
        assert endpoint["tcp_reachable"] is None
        assert endpoint["probe_status"] == "port_unverified"
        assert result["investigation_status"] == "port_unverified"


@pytest.mark.asyncio
async def test_specialist_redis_probe_also_refuses_guessed_port():
    data = {"Redis": {"Endpoints": {"Host": "10.248.34.221"}}}
    encoded = base64.b64encode(json.dumps(data).encode()).decode()

    class Stub:
        def _validate_service(self, service): pass
        async def service_config_discovery(self, *args):
            return {"success": True, "files": [
                {"path": "/app/appsettings.json", "verified_exists": True},
            ]}
        async def _run(self, *args):
            return {"success": True, "stdout": encoded}
        async def tcp_check(self, *args):
            raise AssertionError("Cannot probe guessed vendor default")

    result = await check_redis_config(Stub(), "vm", "gfpapi")
    assert result["status"] == "tcp_unverified"
    assert result["endpoints"][0]["port"] is None
    assert result["endpoints"][0]["tcp_status"] == "port_unverified"


def test_historical_6379_without_port_provenance_cannot_claim_app_success():
    brief = {"alert_focused_report": {
        "alert_message": "GFP_Backend Redis errors reached at least 10 events",
        "next_check_fa": "پورت پیکربندی مؤثر و لاگ کلاینت بررسی شود.",
        "related_checks": [{
            "evidence_ref": "historical-evidence",
            "endpoints": [{
                "kind": "redis", "host": "10.248.34.221",
                "port": 6379, "tcp_reachable": True,
                "config_key": "Redis.Endpoints.Host",
            }],
        }],
    }}
    response = fallback_explanation(brief)
    assert "پورت واقعی و مؤثر برنامه" in response["text"]
    assert "اتصال TCP موفق بوده است" not in response["text"]
    assert "historical-evidence" in response["evidence_refs"]
