"""Regression tests for verified, adaptive dependency troubleshooting."""
from __future__ import annotations

import base64
import json

import pytest

from apps.orchestrator.dynamic_investigation import DynamicInvestigationPlanner
from apps.signal_gateway import SignalGateway, OperationalSignal
from integrations.vm.dependency_discovery import discover
from integrations.vm.dependency_investigation import investigate
from integrations.vm.protocol_diagnostics import redis_unauthenticated_ping
from integrations.vm.ssh_connector import SSHVMConnector
from integrations.vm.tool_contract import validate_vm_observation


def test_redis_connection_uri_and_stackexchange_ssl_do_not_leak_secrets():
    data = {
        "Redis": {
            "Primary": "rediss://alice:ULTRA_SECRET@redis-sec.internal:6380/0",
            "Secondary": "redis-plain.internal:6381,ssl=true,password=ULTRA_SECRET",
        },
    }
    rows = discover(data)
    endpoints = {(row["host"], row["port"]): row for row in rows}
    assert endpoints["redis-sec.internal", 6380]["tls_requested"] is True
    assert endpoints["redis-plain.internal", 6381]["tls_requested"] is True
    assert "ULTRA_SECRET" not in repr(rows)
    assert "alice" not in repr(rows)


@pytest.mark.asyncio
@pytest.mark.parametrize("answer, expected, verified", [
    ("PONG", "unauthenticated_ping_ok", True),
    ("NOAUTH Authentication required.", "authentication_required", False),
    ("NOPERM this user has no permissions", "access_denied", False),
    ("__AIOPS_REDIS_CLI_UNAVAILABLE__", "client_not_installed", False),
    ("SSL_connect: certificate verify failed", "tls_handshake_unverified", False),
])
async def test_redis_protocol_response_is_typed_and_never_exposes_raw_output(
    answer, expected, verified,
):
    class Worker:
        def _validate_target(self, target): assert target == "consumer-vm"
        def _validate_remote_host(self, host): assert host == "redis.internal"
        def _validate_port(self, port): return port
        async def _run(self, target, command):
            assert "redis-cli" in command and " PING " in command
            assert "AUTH" not in command and "password" not in command.lower()
            assert "--tls" in command
            return {"success": True, "stdout": answer}
    record = await redis_unauthenticated_ping(
        Worker(), "consumer-vm", "redis.internal", 6380, tls=True,
    )
    assert record["protocol_status"] == expected
    assert record["protocol_health_verified"] is verified
    assert answer not in repr(record) or answer in {"PONG"}


@pytest.mark.asyncio
async def test_redis_network_failure_runs_consumer_dns_without_ping_or_auth():
    source = base64.b64encode(json.dumps({
        "Redis": {"Connection": "redis://cache.internal:6379"}
    }).encode()).decode()

    class Worker:
        def _validate_target(self, target): assert target == "vm-a"
        def _validate_service(self, service): assert service == "gfpapi"
        async def service_config_discovery(self, target, service):
            return {"success": True, "files": [
                {"path": "/srv/app/appsettings.json", "verified_exists": True}]}
        async def _run(self, target, cmd):
            assert "redis-cli" not in cmd
            return {"success": True, "stdout": source}
        async def tcp_check(self, target, host, port):
            assert (host, port) == ("cache.internal", 6379)
            return {"success": True, "supported": True, "reachable": False}
        async def dns_check(self, target, hostname):
            assert hostname == "cache.internal"
            return {"success": True, "resolved": False}
        async def route_check(self, *args):
            raise AssertionError("DNS failure: no route probe")
    output = await investigate(Worker(), "vm-a", "gfpapi")
    dep = output["dependencies"][0]
    assert dep["tcp_reachable"] is False
    assert dep["dns_resolved"] is False
    assert output["investigation_status"] == "transport_failure_observed"
    assert output["next_checks"] == ["review_dns_configuration"]
    assert output["root_cause_confirmed"] is False
    assert output["application_health_verified"] is False
    assert validate_vm_observation("dependency_investigation", "vm-a", output)


@pytest.mark.asyncio
async def test_authenticated_redis_response_does_not_claim_credentials_invalid():
    source = base64.b64encode(json.dumps({
        "Redis": {"Endpoint": "rediss://user:SECRET@cache.internal:6380"}
    }).encode()).decode()
    class Worker:
        def _validate_target(self, target): pass
        def _validate_service(self, service): pass
        def _validate_remote_host(self, host): assert host == "cache.internal"
        def _validate_port(self, port): return port
        async def service_config_discovery(self, target, service):
            return {"success": True, "files": [{
                "path": "/data/gfpapi/appsettings.Production.json",
                "verified_exists": True,
            }]}
        async def _run(self, target, command):
            if "redis-cli" in command:
                assert " --tls" in command and " PING " in command
                assert "SECRET" not in command
                return {"success": True, "stdout": "NOAUTH Authentication required."}
            return {"success": True, "stdout": source}
        async def tcp_check(self, target, host, port):
            return {"success": True, "supported": True, "reachable": True}
    output = await investigate(Worker(), "vm-a", "gfpapi")
    row = output["dependencies"][0]
    assert row["protocol_status"] == "authentication_required"
    assert row["tls_requested"] is True
    assert row["tcp_reachable"] is True
    assert row["config_file"] == "/data/gfpapi/appsettings.Production.json"
    assert row["config_key"] == "Redis.Endpoint"
    assert output["investigation_status"] == "redis_protocol_responded"
    assert "compare_application_auth_settings" in output["next_checks"]
    assert output["root_cause_confirmed"] is False
    assert output["application_health_verified"] is False
    assert "SECRET" not in repr(output)
    assert validate_vm_observation("dependency_investigation", "vm-a", output)


@pytest.mark.asyncio
async def test_dotnet_publish_root_inventory_checks_environment_file_not_arbitrary_path():
    worker = SSHVMConnector.__new__(SSHVMConnector)
    async def runtime(target, service):
        return {"success": True, "runtime": "dotnet",
                "publish_directory": "/srv/gfpapi/publish",
                "unit_file": "/etc/systemd/system/gfpapi.service",
                "config_candidates": []}
    commands = []
    async def run(target, command):
        commands.append(command)
        if "find " in command:
            assert "/srv/gfpapi/publish" in command
            return {"success": True, "stdout": (
                "/srv/gfpapi/publish/appsettings.Production.json\n"
                "/srv/gfpapi/publish/appsettings.json\n"
                "/srv/gfpapi/publish/appsettings.secret.json\n"
                "/tmp/another/appsettings.Test.json\n"
            )}
        return {"success": True, "stdout": ""}
    worker._validate_service = lambda service: None
    worker.service_runtime_discovery = runtime
    worker._run = run
    output = await worker.service_config_discovery("vm-a", "gfpapi")
    paths = {row["path"] for row in output["files"]
             if row["verified_exists"]}
    assert "/srv/gfpapi/publish/appsettings.json" in paths
    assert "/srv/gfpapi/publish/appsettings.Production.json" in paths
    assert "/tmp/another/appsettings.Test.json" not in paths
    assert output["config_contents_exposed"] is False


@pytest.mark.asyncio
async def test_planner_uses_verified_noauth_and_dns_status_without_setting_target():
    trigger = {
        "source": "elasticsearch", "type": "log",
        "raw_data": {"message": "Redis connection timeout"},
    }
    evidence = {
        "source": "vm_mcp", "type": "telemetry", "raw_data": {
            "success": True, "diagnostic": "dependency_investigation",
            "dependencies": [{
                "kind": "redis", "config_verified": True,
                "probe_status": "tcp_reachable",
                "protocol_status": "authentication_required",
                "config_key": "Redis.Endpoint",
            }],
        },
    }
    proposal = await DynamicInvestigationPlanner.propose({
        "service_name": "gfpapi",
        "context": {"evidence": [trigger, evidence]},
    }, adapter=None)
    assert proposal["dependency_diagnostics"][0]["protocol_status"] == "authentication_required"
    assert proposal["checks"] == []
    assert proposal["execution_authority"] is False
    assert proposal["counts_as_live_evidence"] is False


@pytest.mark.asyncio
async def test_zabbix_proven_vm_unit_can_launch_read_only_dependency_probe(monkeypatch):
    import apps.signal_gateway as gateway
    calls = []
    class Client:
        async def dependency_investigation(self, target, service):
            calls.append((target, service))
            return {"success": True, "status": "checks_completed",
                    "dependencies": [], "root_cause_confirmed": False}
        async def close(self): pass

    monkeypatch.setattr(gateway, "vm_transport_configured", lambda: True)
    monkeypatch.setattr(gateway, "VMEdgeMCPClient", Client)
    source = OperationalSignal(
        source="zabbix", source_id="z-001", signal_type="problem",
        summary="gfpapi Redis timeout", service="gfpapi",
    )
    host = {"status": "verified_by_vm_mcp",
            "verified_target": "10.248.16.82",
            "verified_runtime_service": "gfpapi"}
    proof = {
        "source": "vm_mcp",
        "raw_data": {
            "diagnostic": "service_status", "success": True,
            "load_state": "loaded", "target": "10.248.16.82",
            "service": "gfpapi",
        },
    }
    rows, followup = await SignalGateway._investigate_verified_alert_dependency(
        source, source.to_evidence(), host, [proof], "gfpapi",
    )
    assert calls == [("10.248.16.82", "gfpapi")]
    assert len(rows) == 1
    assert followup["probe_recorded"] is True


@pytest.mark.asyncio
async def test_llm_selected_readonly_followups_require_independent_vm_proof():
    from apps.orchestrator.verified_dependency_followup import (
        run_verified_dependency_followup,
    )
    calls = []
    class Client:
        async def service_logs(self, target, service):
            calls.append(("service_logs", target, service))
            return {"success": True, "target": target,
                    "service": service, "logs": ["Redis timeout"]}
        async def network_status(self, target):
            calls.append(("network_status", target))
            return {"success": True, "target": target, "interfaces": []}
        async def config_change_apply(self, *args):
            raise AssertionError("No write action allowed")
    state = {
        "incident_id": "incident-1", "service_name": "gfpapi",
        "context": {
            "host_discovery": {
                "status": "verified_by_vm_mcp",
                "verified_target": "10.248.16.82",
                "verified_runtime_service": "gfpapi",
            },
            "evidence": [{
                "source": "vm_mcp",
                "raw_data": {
                    "diagnostic": "service_status", "success": True,
                    "load_state": "loaded", "target": "10.248.16.82",
                    "service": "gfpapi",
                },
            }],
        },
    }
    result = await run_verified_dependency_followup(
        Client(), state, ["service_logs", "config_change_apply", "network_status"],
    )
    assert calls == [
        ("service_logs", "10.248.16.82", "gfpapi"),
        ("network_status", "10.248.16.82"),
    ]
    assert [x["raw_data"]["diagnostic"] for x in result] == [
        "service_logs", "network_status",
    ]
    assert all(x["raw_data"]["binding"] ==
               "independent_vm_mcp_service_status" for x in result)
    # If the matching live systemd proof is absent, even selected read tools
    # must not run. Logs, source labels or LLM text are never enough.
    state["context"]["evidence"] = []
    calls.clear()
    blocked = await run_verified_dependency_followup(
        Client(), state, ["service_logs", "network_status"],
    )
    assert blocked == [] and calls == []


@pytest.mark.asyncio
async def test_orchestrator_preserves_verified_gfp_alias_across_context(monkeypatch):
    from apps.orchestrator.signal_aware import SignalAwareE2EOrchestrator
    from domain.contracts.config import settings

    monkeypatch.setattr(settings, "ELASTIC_SERVICE_DISCOVERY_ALIASES",
                        {"GFP_Backend": ["gfpapi"]})

    class Collector:
        async def collect(self, service, since, until=None):
            return {"service": service, "evidence": [], "asset_context": {}}

    workflow = SignalAwareE2EOrchestrator.__new__(SignalAwareE2EOrchestrator)
    workflow.db = None
    workflow.evidence_collector = Collector()
    workflow.progress_emitter = None
    workflow.llm = None
    monkeypatch.setattr(SignalAwareE2EOrchestrator, "_audit",
                        staticmethod(lambda *args, **kwargs: None))

    ref = "elastic-discovery-vm:10.248.16.82:gfpapi"
    proof = {
        "type": "telemetry", "source": "vm_mcp",
        "reference": ref,
        "raw_data": {
            "diagnostic": "service_status", "success": True,
            "target": "10.248.16.82", "service": "gfpapi",
            "unit_id": "gfpapi.service", "load_state": "loaded",
            "source_service_label": "GFP_Backend",
        },
    }
    signal = OperationalSignal(
        source="elasticsearch", source_id="alert-redis-alias",
        signal_type="redis_error_threshold",
        service="GFP_Backend", summary="Redis timeout in GFP Backend",
    )
    state = {
        "incident_id": "alias-incident", "service_name": "gfpapi",
        "evidence_summary": signal.summary,
        "context": {
            "service": "gfpapi",
            "evidence": [proof, signal.to_evidence()],
            "trigger_evidence": [signal.to_evidence()],
            "trigger_signal": signal.model_dump(mode="json"),
            "host_discovery": {
                "status": "verified_by_vm_mcp",
                "verified_target": "10.248.16.82",
                "verified_runtime_service": "gfpapi",
            },
            "verified_runtime_mapping": {
                "source_service": "GFP_Backend",
                "runtime_service": "gfpapi",
                "target": "10.248.16.82",
                "evidence_reference": ref,
                "verification": "vm_mcp_service_status",
            },
        },
        "live_evidence": {"evidence": [proof]},
    }
    result = await workflow._context_node(state)
    assert result["service_name"] == "gfpapi"
    assert result["context"]["verified_runtime_mapping"]["runtime_service"] == "gfpapi"
    assert result["context"]["host_discovery"]["verified_target"] == "10.248.16.82"
