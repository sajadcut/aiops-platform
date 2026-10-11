"""Regression coverage for Zabbix_to_AIOps_Team_Guide_FA v1.1 (18 pages).

Exact JSON names, authoritative event/asset identity, recovery pairing and
non-executable trigger semantics are deliberate contract requirements.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest

from apps.context_service.asset_identity import AssetIdentityResolver
from apps.signal_gateway import signal_from_zabbix
from apps.signal_gateway.zabbix_lifecycle import classify_zabbix_lifecycle
from integrations.vm.target_context import (
    target_from_zabbix_payload,
    target_port_from_zabbix_payload,
)
from integrations.zabbix.webhook_contract import (
    normalize_zabbix_payload,
    zabbix_event_time,
    zabbix_tags,
)


def _asset(payload: dict) -> dict:
    return AssetIdentityResolver.resolve([signal_from_zabbix(payload).to_evidence()])


def test_media_type_script_flat_vm_payload_and_event_timestamp():
    payload = {
        "eventid": "501001", "event_value": "1", "event_status": "PROBLEM",
        "name": "VM memory usage is high", "severity": "High",
        "hostid": "42", "host": "payment-vm-01", "host_name": "Payments VM",
        "host_ip": "10.20.10.99", "triggerid": "21001",
        "operational_data": "Memory utilization=94%",
        "timestamp": "1791712800",
        "tags": [
            {"tag": "platform", "value": "vm"},
            {"tag": "asset_type", "value": "vm"},
            {"tag": "environment", "value": "production"},
            {"tag": "service", "value": "payment-api"},
            {"tag": "target_ip", "value": "10.20.10.15"},
            {"tag": "business_service", "value": "payment"},
            {"tag": "owner", "value": "platform"},
        ],
    }
    normalized = normalize_zabbix_payload(payload)
    signal = signal_from_zabbix(normalized)
    asset = _asset(payload)
    assert signal.source_id == "501001"
    assert signal.severity == "high"
    assert signal.timestamp == datetime.fromtimestamp(1791712800, timezone.utc)
    assert signal.service == "payment-api"
    assert signal.raw_data["operational_data"] == payload["operational_data"]
    assert asset["asset_id"] == "42"
    assert asset["hostname"] == "payment-vm-01"
    assert asset["platform"] == asset["asset_type"] == "vm"
    assert asset["environment"] == "production"
    assert asset["business_service"] == "payment"
    assert asset["owner"] == "platform"
    assert "10.20.10.15" in asset["ip_addresses"]
    assert target_from_zabbix_payload(normalized) == "10.20.10.15"
    assert target_from_zabbix_payload({"host_ip": "10.20.10.99", "host": "payment-vm-01"}) is None


def test_vm_port_and_optional_metadata_are_bounded_and_not_guessed():
    payload = {
        "eventid": "501001",
        "tags": [
            {"tag": "service", "value": "haproxy.service"},
            {"tag": "target_port", "value": "8800"},
            {"tag": "target_ip", "value": "10.100.6.199"},
            {"tag": "filesystem", "value": "/var"},
            {"tag": "fqdn", "value": "host.example.test"},
        ],
        "host_ip": "10.99.99.99",
        "trigger": "tcp port 9900 down",
    }
    normalized = normalize_zabbix_payload(payload)
    assert normalized["target_port"] == 8800
    assert normalized["filesystem"] == "/var"
    assert normalized["fqdn"] == "host.example.test"
    assert target_port_from_zabbix_payload(normalized) == 8800
    assert _asset(payload)["tags"]["filesystem"] == "/var"
    for invalid in ["8800x", "0", "65536", "{EVENT.TAG}", -1, None]:
        changed = dict(payload, target_port=invalid, tags=[])
        assert target_port_from_zabbix_payload(normalize_zabbix_payload(changed)) is None
    assert target_port_from_zabbix_payload({"trigger": "port 8800 down"}) is None


@pytest.mark.parametrize(
    ("payload", "expected"),
    [
        ({
            "eventid": "601001", "name": "Kubernetes workload payment-api has pod in CrashLoopBackOff",
            "platform": "kubernetes", "asset_type": "kubernetes_workload",
            "cluster": "prod-k8s", "namespace": "payment", "workload_kind": "Deployment",
            "workload": "payment-api", "service": "payment-api",
            "pod": "payment-api-7ddf6859cd-x2h6m", "node": "worker-03",
        }, {"platform": "kubernetes", "asset_type": "kubernetes_workload",
            "cluster": "prod-k8s", "namespace": "payment",
            "workload_kind": "Deployment", "workload": "payment-api",
            "pod": "payment-api-7ddf6859cd-x2h6m", "node": "worker-03"}),
        ({
            "eventid": "601101", "name": "Kubernetes namespace cognia memory usage is high",
            "platform": "kubernetes", "asset_type": "kubernetes_namespace",
            "cluster": "prod-k8s", "namespace": "cognia", "service": "cognia",
        }, {"platform": "kubernetes", "asset_type": "kubernetes_namespace",
            "cluster": "prod-k8s", "namespace": "cognia", "service": "cognia"}),
        ({
            "eventid": "501201", "name": "Network connectivity lost to payment-vm-01",
            "platform": "network", "asset_type": "network", "service": "payment-api",
            "device": "core-sw-01", "interface": "Gi0/1",
            "endpoint": "10.20.10.15:8443", "target_ip": "10.20.10.15",
        }, {"platform": "network", "asset_type": "network",
            "service": "payment-api"}),
        ({
            "eventid": "501301", "name": "Database slow",
            "platform": "vm", "asset_type": "database", "service": "postgresql",
            "database": "paymentdb", "db_engine": "postgresql",
            "db_instance": "postgres-prod-01", "target_port": 5432,
        }, {"platform": "vm", "asset_type": "database", "service": "postgresql"}),
        ({
            "eventid": "501401", "name": "App error",
            "platform": "application", "asset_type": "application",
            "service": "payment-api", "fqdn": "payment.example.com",
            "endpoint": "https://payment.example.com/health",
        }, {"platform": "application", "asset_type": "application",
            "service": "payment-api"}),
    ],
)
def test_guide_asset_scenarios_keep_stable_domain_identity(payload, expected):
    asset = _asset(payload)
    for key, value in expected.items():
        assert asset[key] == value, (key, asset)
    if payload.get("workload_kind"):
        assert asset["workload_kind"] == "Deployment"
    for optional in ("device", "interface", "database", "db_engine", "db_instance", "fqdn", "endpoint"):
        if payload.get(optional):
            assert asset["tags"][optional] == payload[optional]


def test_tags_json_and_unknown_macro_are_handled_without_false_identity():
    tags = [
        {"tag": "Service", "value": "payment-api"},
        {"tag": "platform", "value": "kubernetes"},
        {"tag": "namespace", "value": "cognia"},
        {"tag": "workload", "value": "{EVENT.MISSING.TAG}"},
    ]
    normalized = normalize_zabbix_payload({
        "eventid": "601101", "tags": json.dumps(tags),
        "recovery_eventid": "{EVENT.RECOVERY.ID}", "host_ip": "*UNKNOWN*",
    })
    assert normalized["service"] == "payment-api"
    assert normalized["namespace"] == "cognia"
    assert "workload" not in normalized
    assert normalized["recovery_eventid"] == ""
    assert normalized["host_ip"] == ""
    assert len(zabbix_tags(json.dumps(tags))) == 4


def test_problem_and_recovery_identifiers_match_document_appendix_a6():
    problem = {
        "eventid": "501001", "event_value": "1",
        "event_status": "PROBLEM", "name": "VM memory usage is high",
    }
    recovery = {
        "eventid": "501001", "recovery_eventid": "501009",
        "event_value": "0", "event_status": "RESOLVED",
        "recovery_timestamp": "1791713100",
    }
    p = classify_zabbix_lifecycle(normalize_zabbix_payload(problem))
    r = classify_zabbix_lifecycle(normalize_zabbix_payload(recovery))
    assert p["state"] == "problem"
    assert p["source_id"] == "501001"
    assert r["state"] == "recovery"
    assert r["problem_event_id"] == p["source_id"]
    assert r["source_id"] == r["recovery_event_id"] == "501009"


@pytest.mark.parametrize("bad", ["", "UNKNOWN", "*UNKNOWN*", "{EVENT.ID}", None])
def test_missing_or_unexpanded_eventid_is_rejected_for_deduplication(bad):
    with pytest.raises(ValueError, match="zabbix_eventid_required"):
        normalize_zabbix_payload({"eventid": bad})


def test_timestamp_supports_epoch_iso_and_empty_without_guessing():
    expect = datetime.fromtimestamp(1791712800, timezone.utc)
    assert zabbix_event_time("1791712800") == expect
    assert zabbix_event_time("1791712800000") == expect
    assert zabbix_event_time(expect.isoformat()) == expect
    assert zabbix_event_time("{EVENT.TIMESTAMP}") is None
    assert zabbix_event_time("invalid") is None


def test_no_trigger_based_vm_execution_identity():
    payload = {
        "eventid": "501201", "name": "restart nginx on 10.10.0.10",
        "host": "10.10.0.10", "host_ip": "10.10.0.10",
        "service": "nginx", "target_port": "not valid",
        "tags": [{"tag": "asset_type", "value": "vm"}],
    }
    normalized = normalize_zabbix_payload(payload)
    assert target_from_zabbix_payload(normalized) is None
    assert target_port_from_zabbix_payload(normalized) is None
    assert _asset(payload)["service"] == "nginx"


@pytest.mark.asyncio
async def test_api_ingestion_passes_normalized_guide_payload_to_lifecycle(monkeypatch):
    from apps.api import signals as signals_api
    from integrations.vm.target_context import current_vm_port, current_vm_target

    recorded = {}

    class FakeDB:
        async def __aenter__(self):
            return self
        async def __aexit__(self, exc_type, exc, tb):
            return False

    async def fake_database_ready(db):
        return None

    async def fake_lifecycle(db, payload):
        recorded.update(payload)
        assert current_vm_target() == "10.20.10.15"
        assert current_vm_port() == 8800
        return {"status": "accepted", "incident_id": "incident-501001", "signal_state": "problem"}

    monkeypatch.setattr(signals_api, "AsyncSessionLocal", FakeDB)
    monkeypatch.setattr(signals_api, "_require_database_ready", fake_database_ready)
    monkeypatch.setattr(signals_api, "ingest_zabbix_payload", fake_lifecycle)

    result = await signals_api._ingest_zabbix({
        "eventid": "501001", "event_value": "1",
        "host": "payment-vm-01", "host_ip": "192.0.2.200",
        "tags": [
            {"tag": "service", "value": "payment-api"},
            {"tag": "target_ip", "value": "10.20.10.15"},
            {"tag": "target_port", "value": "8800"},
        ],
    })
    assert result["incident_id"] == "incident-501001"
    assert recorded["service"] == "payment-api"
    assert recorded["target_ip"] == "10.20.10.15"
    assert recorded["target_port"] == 8800
    assert current_vm_target() is None
    assert current_vm_port() is None


@pytest.mark.asyncio
async def test_api_rejects_missing_source_event_identity_before_calling_db(monkeypatch):
    from fastapi import HTTPException
    from apps.api import signals as signals_api

    def no_database_session():
        raise AssertionError("Invalid webhook must not open a DB session")

    monkeypatch.setattr(signals_api, "AsyncSessionLocal", no_database_session)
    with pytest.raises(HTTPException) as exc:
        await signals_api._ingest_zabbix({"eventid": "{EVENT.ID}"})
    assert exc.value.status_code == 422
    assert exc.value.detail == "zabbix_eventid_required"


@pytest.mark.asyncio
async def test_recovery_without_parent_incident_is_retryable_not_silently_acknowledged(monkeypatch):
    from fastapi import HTTPException
    from apps.api import signals as signals_api

    class FakeDB:
        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return False

    async def ready(db):
        return None

    async def unmatched(db, payload):
        return {
            "signal_state": "recovery",
            "recovery_unmatched": True,
            "terminal_reason": "zabbix_recovery_problem_event_not_found",
        }

    monkeypatch.setattr(signals_api, "AsyncSessionLocal", FakeDB)
    monkeypatch.setattr(signals_api, "_require_database_ready", ready)
    monkeypatch.setattr(signals_api, "ingest_zabbix_payload", unmatched)

    with pytest.raises(HTTPException) as result:
        await signals_api._ingest_zabbix({
            "eventid": "501001", "recovery_eventid": "501009",
            "event_value": "0", "event_status": "RESOLVED",
        })
    assert result.value.status_code == 503
    assert result.value.headers == {"Retry-After": "10"}
    assert result.value.detail == "zabbix_recovery_problem_event_not_found"


@pytest.mark.asyncio
async def test_recovery_without_recovery_id_is_explicit_contract_error(monkeypatch):
    from fastapi import HTTPException
    from apps.api import signals as signals_api

    class FakeDB:
        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return False

    async def ready(db):
        return None

    async def invalid(db, payload):
        return {
            "signal_state": "recovery",
            "recovery_unmatched": True,
            "terminal_reason": "zabbix_recovery_parent_event_missing",
        }

    monkeypatch.setattr(signals_api, "AsyncSessionLocal", FakeDB)
    monkeypatch.setattr(signals_api, "_require_database_ready", ready)
    monkeypatch.setattr(signals_api, "ingest_zabbix_payload", invalid)

    with pytest.raises(HTTPException) as result:
        await signals_api._ingest_zabbix({
            "eventid": "501001", "event_value": "0",
        })
    assert result.value.status_code == 422
    assert result.value.detail == "zabbix_recovery_parent_event_missing"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("asset_tags", "expected_ns", "expected_vm_blocked"),
    [
        ({"platform": "kubernetes", "asset_type": "kubernetes_workload", "namespace": "payment"}, "payment", True),
        ({"platform": "kubernetes", "asset_type": "kubernetes_namespace", "namespace": "cognia"}, "cognia", True),
        ({"platform": "network", "asset_type": "network", "namespace": "payment"}, None, True),
        ({"platform": "application", "asset_type": "application", "namespace": "payment"}, None, True),
    ],
)
async def test_non_vm_webhooks_keep_namespace_and_vm_probe_guards_request_scoped(
    monkeypatch, asset_tags, expected_ns, expected_vm_blocked
):
    from apps.api import signals as signals_api
    from integrations.kubernetes.target_context import current_kubernetes_namespace
    from integrations.vm.target_context import current_vm_target, vm_probes_blocked

    class FakeDB:
        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return False

    async def ready(db):
        return None

    async def lifecycle(db, payload):
        assert current_kubernetes_namespace() == expected_ns
        assert vm_probes_blocked() is expected_vm_blocked
        assert current_vm_target() is None
        return {"status": "accepted", "incident_id": "incident-501001"}

    monkeypatch.setattr(signals_api, "AsyncSessionLocal", FakeDB)
    monkeypatch.setattr(signals_api, "_require_database_ready", ready)
    monkeypatch.setattr(signals_api, "ingest_zabbix_payload", lifecycle)
    await signals_api._ingest_zabbix({
        "eventid": "501001", "event_value": "1",
        "target_ip": "10.10.0.1", "service": "payment-api",
        **asset_tags,
    })
    assert current_kubernetes_namespace() is None
    assert vm_probes_blocked() is False
    assert current_vm_target() is None


@pytest.mark.asyncio
async def test_zabbix_namespace_is_passed_to_kubernetes_mcp_not_global_default(monkeypatch):
    from integrations.kubernetes.mcp_client import KubernetesMCPClient
    from domain.contracts.config import settings

    called = []

    async def call_tool(self, name, args):
        called.append((name, args))
        return {}

    monkeypatch.setattr(KubernetesMCPClient, "call_tool", call_tool)
    monkeypatch.setattr(KubernetesMCPClient, "json_content", staticmethod(lambda result: []))
    monkeypatch.setattr(settings, "KUBERNETES_NAMESPACE", "default")
    client = object.__new__(KubernetesMCPClient)

    assert await client.collect_evidence("payment-api", namespace="payment") == []
    assert called == [(
        "collect_kubernetes_evidence",
        {"operation": "service_evidence", "namespace": "payment", "service": "payment-api"},
    )]

    await client.collect_evidence("cognia")
    assert called[-1][1]["namespace"] == "default"


@pytest.mark.asyncio
async def test_evidence_collector_preserves_zabbix_request_namespace():
    from apps.context_service.evidence_collector import EvidenceCollector
    from integrations.kubernetes.target_context import (
        bind_kubernetes_namespace, reset_kubernetes_namespace
    )

    class K8s:
        enabled = True

        def __init__(self):
            self.queries = []

        async def collect_evidence(self, service, *, namespace=None):
            self.queries.append((service, namespace))
            return []

    k8s = K8s()
    collector = EvidenceCollector(kubernetes=k8s)
    token = bind_kubernetes_namespace("cognia")
    try:
        await collector.collect("cognia", datetime.now(timezone.utc))
    finally:
        reset_kubernetes_namespace(token)
    assert k8s.queries == [("cognia", "cognia")]


def test_exact_v11_media_type_fields_are_preserved_by_receiver():
    from apps.api.signals import RawSignalPayload

    fields = {
        "eventid": "501001",
        "event_value": "1",
        "event_status": "PROBLEM",
        "name": "VM memory usage is high",
        "severity": "High",
        "hostid": "9001",
        "host": "vm-payment-01",
        "host_name": "Payment VM",
        "host_ip": "10.20.10.99",
        "triggerid": "21001",
        "trigger": "Memory usage high",
        "tags": [{"tag": "platform", "value": "vm"}],
        "operational_data": "Memory utilization=94%",
        "acknowledged": "No",
        "timestamp": "1791712800",
    }
    request = RawSignalPayload.model_validate({"payload": fields})
    normalized = normalize_zabbix_payload(request.payload)
    for key, value in fields.items():
        assert normalized[key] == value
    assert "api_key" not in normalized
    assert "url" not in normalized
    recovery = normalize_zabbix_payload({
        "eventid": "501001", "event_value": "0",
        "recovery_eventid": "501009",
        "recovery_timestamp": "1791713100",
    })
    assert recovery["recovery_eventid"] == "501009"
    assert recovery["recovery_timestamp"] == "1791713100"


def test_zabbix_route_keeps_api_key_auth_and_high_volume_rate_limit():
    from apps.api import signals as signals_api
    from domain.contracts.rate_limit import rate_limiter_loose

    route = next(
        row for row in signals_api.router.routes
        if getattr(row, "path", None) == "/signals/zabbix"
    )
    assert any(
        depends.dependency is rate_limiter_loose
        for depends in route.dependencies
    )
    auth = [
        dependency for dependency in route.dependant.dependencies
        if "require_permission" in getattr(dependency.call, "__qualname__", "")
        or getattr(dependency.call, "__name__", "") == "dependency"
    ]
    assert auth


def test_zabbix_kubernetes_node_identity_is_not_inferred_from_pod():
    signal = signal_from_zabbix({
        "eventid": "601201",
        "event_value": "1",
        "name": "Kubernetes node worker-03 is under pressure",
        "platform": "kubernetes",
        "asset_type": "kubernetes_node",
        "cluster": "prod-k8s",
        "node": "worker-03",
        "owner": "infrastructure",
        "datacenter": "dc1",
    })
    asset = AssetIdentityResolver.resolve([signal.to_evidence()])
    assert asset["platform"] == "kubernetes"
    assert asset["asset_type"] == "kubernetes_node"
    assert asset["node"] == "worker-03"
    assert asset["cluster"] == "prod-k8s"
    assert asset["owner"] == "infrastructure"
    assert asset["pod"] is None
