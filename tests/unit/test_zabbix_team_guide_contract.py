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
