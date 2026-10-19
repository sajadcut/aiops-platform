"""Regression for the October 19 database alert on a Redis-heavy VM."""
import base64
import json

import pytest

from apps.decision_brief import build_decision_brief
from integrations.vm import dependency_investigation


@pytest.mark.asyncio
async def test_llm_not_configured_is_not_hidden_by_later_empty_files(monkeypatch):
    def payload(data):
        return base64.b64encode(json.dumps(data).encode()).decode()

    outputs = [
        payload({"Redis": {"Host": "cache.internal", "Port": 6389}}),
        payload({"Logging": {"Level": "Info"}}),
    ]
    async def binding(config):
        has_hosts = "Redis" in config
        return {
            "status": ("trusted_llm_not_configured" if has_hosts else
                       "no_safe_host_port_candidates"),
            "endpoints": [],
            "candidate_host_count": 1 if has_hosts else 0,
            "candidate_port_count": 1 if has_hosts else 0,
            "candidate_inline_endpoint_count": 0,
        }
    monkeypatch.setattr(dependency_investigation, "resolve_llm_bindings", binding)

    class Worker:
        count = 0
        def _validate_target(self, target):
            assert target == "vm"
        def _validate_service(self, service):
            assert service == "gfpapi"
        async def service_config_discovery(self, target, service):
            return {"success": True, "files": [
                {"path": "/srv/prod/appsettings.json", "verified_exists": True},
                {"path": "/srv/prod/bootstrap.json", "verified_exists": True},
            ]}
        async def _run(self, target, command):
            value = outputs[self.count]
            self.count += 1
            return {"success": True, "stdout": value}
        async def tcp_check(self, target, host, port):
            assert (host, port) == ("cache.internal", 6389)
            return {"success": True, "supported": True, "reachable": False}
        async def dns_check(self, *args):
            return {"success": True, "resolved": False}

    result = await dependency_investigation.investigate(Worker(), "vm", "gfpapi")
    assert result["config_files_checked"] == 2
    assert result["llm_field_binding_status"] == "trusted_llm_not_configured"
    assert [f["status"] for f in result["llm_field_binding_files"]] == [
        "trusted_llm_not_configured", "no_safe_host_port_candidates",
    ]
    assert result["checks_executed"] == 1


def test_database_alert_reports_redis_probes_as_irrelevant():
    from datetime import datetime, timezone
    name = "GFP_Backend database connection errors reached at least 10 events"
    result = build_decision_brief(
        incident={
            "id": "test-db-alert", "service": "gfpapi", "severity": "high",
            "status": "analyzing", "summary": name,
            "context": {"source": "zabbix"},
        },
        operator_summary={"likely_cause": "unverified"},
        checkpoint={"state": {}, "version": 1},
        durable_evidence=[
            {
                "id": "zabbix-db", "source": "zabbix",
                "created_at": "2026-10-19T20:19:52Z",
                "raw_data": {
                    "name": name, "signal_type": name,
                    "signal_summary": name, "service": "gfpapi",
                    "event_value": "1",
                },
            },
            {
                "id": "vm-dependency", "source": "vm_mcp",
                "created_at": "2026-10-19T20:20:58Z",
                "raw_data": {
                    "mcp_server": "vm_mcp", "tool_name": "dependency_investigation",
                    "success": True, "service": "gfpapi",
                    "status": "checks_completed", "checks_executed": 2,
                    "config_files_read": 4, "config_files_checked": 4,
                    "config_files_parse_failed": 0,
                    "llm_field_binding_status": "trusted_llm_not_configured",
                    "llm_field_binding_files": [{
                        "config_file": "/srv/prod/appsettings.json",
                        "status": "trusted_llm_not_configured",
                        "candidate_host_count": 6,
                        "candidate_port_count": 6,
                        "candidate_inline_endpoint_count": 0,
                        "verified_pair_count": 0,
                    }],
                    "dependencies": [{
                        "kind": "redis", "host": "cache.internal",
                        "port": 6389, "port_inferred": False,
                        "probe_status": "tcp_reachable", "tcp_reachable": True,
                    }, {
                        "kind": "https", "host": "consul.internal",
                        "port": 8443, "port_inferred": False,
                        "probe_status": "unavailable",
                    }],
                },
            },
        ],
        findings=[], audit_events=[],
        now=datetime(2026, 10, 19, 20, 21, tzinfo=timezone.utc),
    )
    report = result["alert_focused_report"]
    assert report["family"] == "database"
    assert report["status"] == "no_relevant_checks"
    assert report["related_checks"] == []
    diag = report["dependency_extraction_diagnostics"][0]
    assert diag["alert_family"] == "database"
    assert diag["matching_endpoint_count"] == 0
    assert diag["other_dependency_kinds"] == ["https", "redis"]
    assert diag["binding_status"] == "trusted_llm_not_configured"
    assert diag["files"][0]["host_fields"] == 6
    assert report["root_cause_confirmed"] is False


@pytest.mark.asyncio
async def test_mixed_application_config_does_not_starve_database_after_six_redis_peers(monkeypatch):
    config = {
        "Redis": {"Endpoints": [
            f"redis-{i}.internal:{6380+i}" for i in range(6)
        ]},
        "ConnectionStrings": {
            "Primary": "postgresql://user:secret@pg.internal:6543/main",
        },
    }
    encoded = base64.b64encode(json.dumps(config).encode()).decode()
    probed = []

    async def no_llm(config):
        return {
            "status": "trusted_llm_not_configured", "endpoints": [],
            "candidate_host_count": 0, "candidate_port_count": 0,
            "candidate_inline_endpoint_count": 0,
        }
    monkeypatch.setattr(dependency_investigation, "resolve_llm_bindings", no_llm)

    class Worker:
        def _validate_target(self, target):
            assert target == "vm"
        def _validate_service(self, service):
            assert service == "gfpapi"
        async def service_config_discovery(self, target, service):
            return {"success": True, "files": [{
                "path": "/srv/prod/appsettings.json", "verified_exists": True,
            }]}
        async def _run(self, target, command):
            return {"success": True, "stdout": encoded}
        async def tcp_check(self, target, host, port):
            probed.append((host, port))
            return {"success": True, "supported": True, "reachable": False}
        async def dns_check(self, *args):
            return {"success": True, "resolved": False}

    result = await dependency_investigation.investigate(Worker(), "vm", "gfpapi")
    assert len(result["dependencies"]) == 6
    assert ("pg.internal", 6543) in probed
    assert any(x["kind"] == "postgresql" and x["port_inferred"] is False
               and x["tcp_reachable"] is False
               for x in result["dependencies"])
    assert all(x["config_file"] == "/srv/prod/appsettings.json"
               for x in result["dependencies"])
    assert "secret" not in str(result)
