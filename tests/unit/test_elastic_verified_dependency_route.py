"""Regression: Redis and all downstream alerts must reach the verified VM path."""
from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import AsyncMock

import pytest

from apps.signal_gateway import SignalGateway, OperationalSignal

TARGET = "10.248.16.82"
SERVICE = "gfpapi"
HOST_DISCOVERY = {
    "status": "verified_by_vm_mcp",
    "verified_target": TARGET,
    "verified_runtime_service": SERVICE,
}
VERIFIED = {
    "type": "telemetry", "source": "vm_mcp",
    "reference": f"elastic-discovery-vm:{TARGET}:{SERVICE}",
    "raw_data": {
        "diagnostic": "service_status", "success": True, "target": TARGET,
        "service": SERVICE, "load_state": "loaded",
    },
}


def signal(message="GFP API Redis errors reached at least 10 events in the last 2 minutes."):
    return OperationalSignal(
        source="elasticsearch", source_id="redis-incident-111",
        signal_type="redis_error_threshold",
        severity="high", summary=message, service="GFP_Backend",
        raw_data={"event": {"action": "redis_error_threshold"}},
    )


@pytest.mark.asyncio
async def test_redis_alert_inspects_verified_gfpapi_systemd_config(monkeypatch):
    import apps.signal_gateway as gateway
    calls = []
    class Client:
        async def dependency_investigation(self, target, service):
            calls.append((target, service))
            return {
                "success": True, "status": "checks_completed", "target": target,
                "service": service, "config_files_checked": 1,
                "config_files_read": 1, "checks_executed": 1,
                "dependencies": [{
                    "kind": "redis", "host": "redis.internal", "port": 6379,
                    "config_file": "/data/gfpapi/appsettings.json",
                    "config_key": "Redis.Endpoint", "tcp_reachable": False,
                }], "secrets_exposed": False,
            }
        async def close(self):
            pass

    monkeypatch.setattr(gateway, "vm_transport_configured", lambda: True)
    monkeypatch.setattr(gateway, "VMEdgeMCPClient", Client)
    result, status = await SignalGateway._investigate_verified_alert_dependency(
        signal(), signal().to_evidence(), HOST_DISCOVERY,
        [VERIFIED], SERVICE,
    )
    assert calls == [(TARGET, SERVICE)]
    assert status["status"] == "checks_completed"
    assert status["probe_recorded"] is True
    assert result[0]["raw_data"]["diagnostic"] == "dependency_investigation"
    assert result[0]["raw_data"]["binding"] == "independent_vm_mcp_service_status"
    assert result[0]["raw_data"]["dependencies"][0]["config_key"] == "Redis.Endpoint"


@pytest.mark.asyncio
@pytest.mark.parametrize("host,rows,runtime", [
    ({**HOST_DISCOVERY, "status": "candidates_found"}, [VERIFIED], SERVICE),
    ({**HOST_DISCOVERY, "verified_target": "evil.invalid"}, [VERIFIED], SERVICE),
    (HOST_DISCOVERY, [], SERVICE),
    (HOST_DISCOVERY, [{**VERIFIED, "raw_data": {
        **VERIFIED["raw_data"], "load_state": "not-found",
    }}], SERVICE),
    (HOST_DISCOVERY, [VERIFIED], "unrelated-service"),
])
async def test_no_verified_runtime_binding_means_no_dependency_probe(
    monkeypatch, host, rows, runtime,
):
    import apps.signal_gateway as gateway
    monkeypatch.setattr(gateway, "vm_transport_configured", lambda: True)
    def forbidden():
        raise AssertionError("unverified VM target must never be probed")
    monkeypatch.setattr(gateway, "VMEdgeMCPClient", forbidden)
    result, status = await SignalGateway._investigate_verified_alert_dependency(
        signal(), signal().to_evidence(), host, rows, runtime,
    )
    assert result == []
    assert status["status"] in {
        "verified_runtime_target_required", "independent_vm_proof_missing",
    }


@pytest.mark.asyncio
async def test_dependency_alert_does_not_consult_mcp_without_trigger(monkeypatch):
    import apps.signal_gateway as gateway
    monkeypatch.setattr(gateway, "vm_transport_configured", lambda: True)
    monkeypatch.setattr(gateway, "VMEdgeMCPClient", lambda: 1 / 0)
    no_dependency = signal("GFP API processing completed")
    rows, status = await SignalGateway._investigate_verified_alert_dependency(
        no_dependency, no_dependency.to_evidence(), HOST_DISCOVERY,
        [VERIFIED], SERVICE,
    )
    assert rows == []
    assert status["status"] == "not_needed"


@pytest.mark.asyncio
async def test_probe_error_is_typed_and_ingestion_can_continue(monkeypatch):
    import apps.signal_gateway as gateway
    class Client:
        async def dependency_investigation(self, target, service):
            raise TimeoutError("local test timeout")
        async def close(self):
            pass
    monkeypatch.setattr(gateway, "vm_transport_configured", lambda: True)
    monkeypatch.setattr(gateway, "VMEdgeMCPClient", Client)
    rows, status = await SignalGateway._investigate_verified_alert_dependency(
        signal(), signal().to_evidence(), HOST_DISCOVERY,
        [VERIFIED], SERVICE,
    )
    assert rows == []
    assert status["status"] == "probe_unavailable"


@pytest.mark.asyncio
async def test_signal_aware_merges_ingress_dependency_into_specialist_evidence(monkeypatch):
    from apps.orchestrator.signal_aware import SignalAwareE2EOrchestrator
    from apps.context_service.service_identity import ServiceIdentityResolver

    class Collector:
        async def collect(self, service, since):
            return {"service": service, "evidence": [], "asset_context": {}}
    workflow = SignalAwareE2EOrchestrator.__new__(SignalAwareE2EOrchestrator)
    workflow.db = None
    workflow.progress_emitter = None
    workflow.evidence_collector = Collector()
    workflow.llm = None
    monkeypatch.setattr(SignalAwareE2EOrchestrator, "_audit",
                        staticmethod(lambda *a, **kw: None))
    row = {
        "type": "telemetry", "source": "vm_mcp",
        "reference": "verified-dependency:elasticsearch:redis-incident-111",
        "raw_data": {
            "diagnostic": "dependency_investigation", "success": True,
            "service": SERVICE, "target": TARGET,
            "binding": "independent_vm_mcp_service_status",
            "dependencies": [{
                "kind": "redis", "host": "redis.internal", "port": 6379,
            }],
        },
    }
    s = signal()
    initial = {
        "incident_id": "inc-test", "service_name": SERVICE,
        "evidence_summary": s.summary,
        "live_evidence": {"evidence": [VERIFIED, row]},
        "context": {
            "service": SERVICE,
            "trigger_signal": s.model_dump(mode="json"),
            "trigger_evidence": [s.to_evidence()],
            "verified_dependency_evidence": [row],
            "incident": {"service": SERVICE, "summary": s.summary},
        },
    }
    # Base context retrieval is deterministic and empty. No LLM should be
    # needed when source-bound systemd runtime is independently verified.
    output = await workflow._context_node(initial)
    dependency = [
        item for item in output["context"]["evidence"]
        if isinstance(item, dict)
        and (item.get("raw_data") or {}).get("diagnostic") == "dependency_investigation"
    ]
    assert len(dependency) == 1
    assert dependency[0]["raw_data"]["dependencies"][0]["kind"] == "redis"


@pytest.mark.asyncio
async def test_duplicate_redis_alert_persists_fresh_probe_without_restarting_workflow(monkeypatch):
    import apps.signal_gateway as gateway
    from unittest.mock import AsyncMock

    sig = signal()
    evidence = {
        "type": "telemetry", "source": "vm_mcp",
        "reference": "verified-dependency:elasticsearch:redis-incident-111",
        "raw_data": {
            "diagnostic": "dependency_investigation", "success": True,
            "binding": "independent_vm_mcp_service_status",
            "service": SERVICE, "target": TARGET,
            "dependencies": [{"kind": "redis", "port": 6379,
                              "tcp_reachable": False}],
        },
    }
    class Repository:
        def __init__(self, session): pass
        async def find_incident_by_evidence_reference(self, **kw):
            assert kw == {"source": "elasticsearch", "reference": sig.source_id}
            return "existing-incident"
    class Checkpoints:
        saved = []
        def __init__(self, session): pass
        async def load(self, incident_id):
            return {"status": "completed", "state": {
                "incident_id": incident_id,
                "context": {"evidence": [sig.to_evidence()]},
                "live_evidence": {"evidence": []},
            }}
        async def save(self, incident_id, state, status="paused"):
            Checkpoints.saved.append((incident_id, state, status))
    async def discover(sig, trigger):
        return {
            "asset_context": {"service": "gfpapi"},
            "service_identity": {"service": "gfpapi"},
            "dependency_evidence": [evidence],
            "dependency_followup": {"status": "checks_completed"},
            "host_discovery": HOST_DISCOVERY,
            "verified_runtime_mapping": None,
        }
    monkeypatch.setattr(gateway, "IncidentRepository", Repository)
    monkeypatch.setattr(gateway, "WorkflowCheckpointStore", Checkpoints)
    monkeypatch.setattr(gateway.SignalGateway, "_knowledge_assisted_asset", staticmethod(discover))
    monkeypatch.setattr(
        gateway.LearningDurableWorkflowRuntime, "start",
        AsyncMock(side_effect=AssertionError("Never start a second workflow")),
    )
    result = await gateway.SignalGateway.ingest(object(), sig)
    assert result["deduplicated"] is True
    assert len(Checkpoints.saved) == 1
    incident_id, saved, status = Checkpoints.saved[0]
    assert incident_id == "existing-incident"
    assert status == "completed"
    assert saved["context"]["verified_dependency_evidence"] == [evidence]
    assert saved["live_evidence"]["evidence"] == [evidence]
    assert saved["context"]["evidence"][-1] == evidence
