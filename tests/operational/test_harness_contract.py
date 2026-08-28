from __future__ import annotations

import os
from pathlib import Path

import pytest

from tests.operational.run_operational_acceptance import (
    BlockedScenario,
    OperationalAcceptanceError,
    SafetyGate,
    load_scenarios,
)


def test_operational_catalog_has_required_real_world_coverage():
    scenarios = load_scenarios()
    ids = {item["id"] for item in scenarios}
    required = {
        "VM-SERVICE-DOWN", "APP-CRASH", "APP-HTTP-5XX", "APP-LATENCY",
        "HOST-CPU-SATURATION", "HOST-MEMORY-OOM", "HOST-DISK-FULL", "HOST-INODE-FULL",
        "PG-CONNECTION-EXHAUSTION", "PG-DEADLOCK", "PG-SLOW-QUERY",
        "K8S-CRASHLOOP", "K8S-OOMKILLED", "K8S-READINESS-FAIL", "K8S-BAD-ROLLOUT",
        "NETWORK-DNS-FAIL", "NETWORK-PACKET-LOSS", "DEPENDENCY-OUTAGE",
        "OBS-ELASTICSEARCH-DOWN", "OBS-PROMETHEUS-DOWN", "OBS-ZABBIX-DOWN",
        "IDENTITY-JWKS-FAIL", "CONFIG-REGRESSION", "TLS-CERT-FAIL",
        "MESSAGING-CONSUMER-LAG", "RECOVERY-BACKUP-FAIL",
        "FALSE-POSITIVE-ALERT", "CONFLICTING-TELEMETRY", "MISSING-TELEMETRY",
        "MCP-TIMEOUT", "LLM-TIMEOUT", "LLM-UNSAFE-OUTPUT", "REMEDIATION-FAILURE",
        "VERIFICATION-FAILURE", "APPROVAL-REJECTED", "APPROVAL-EXPIRED",
        "DUPLICATE-SIGNAL", "REPEATED-INCIDENT", "CONCURRENT-INCIDENTS",
    }
    assert required <= ids
    assert len(ids) == len(scenarios)


def test_every_destructive_scenario_has_typed_injection_rollback_and_acceptance_contract():
    required_expected = {
        "incident", "correlation", "evidence", "agents", "rca", "confidence",
        "decision", "approval_required", "remediation", "verification", "audit_events",
    }
    for scenario in load_scenarios():
        assert scenario.get("service"), scenario["id"]
        assert scenario.get("target"), scenario["id"]
        assert scenario.get("preconditions"), scenario["id"]
        assert required_expected <= set((scenario.get("expected") or {}).keys()), scenario["id"]
        monitoring = scenario.get("monitoring") or {}
        assert monitoring.get("expected_sources"), scenario["id"]
        if scenario.get("destructive", True):
            injection = scenario.get("injection") or {}
            rollback = scenario.get("rollback") or {}
            assert injection.get("action"), scenario["id"]
            assert rollback.get("action"), scenario["id"]
            assert not any(key in injection for key in ("command", "shell", "argv")), scenario["id"]


def test_production_environment_is_unconditionally_rejected(monkeypatch):
    monkeypatch.setenv("ALLOW_DESTRUCTIVE_TESTS", "true")
    monkeypatch.setenv("AIOPS_TEST_ALLOWED_TARGETS", "payments")
    scenario = {
        "id": "X", "destructive": True, "target": "payments",
        "rollback": {"action": "app.restore"},
    }
    with pytest.raises(OperationalAcceptanceError, match="forbidden_in_production"):
        SafetyGate("production").validate(scenario)


def test_destructive_execution_requires_explicit_opt_in_and_target_allowlist(monkeypatch):
    scenario = {
        "id": "X", "destructive": True, "target": "payments",
        "rollback": {"action": "app.restore"},
    }
    monkeypatch.delenv("ALLOW_DESTRUCTIVE_TESTS", raising=False)
    monkeypatch.setenv("AIOPS_TEST_ALLOWED_TARGETS", "payments")
    with pytest.raises(BlockedScenario, match="ALLOW_DESTRUCTIVE_TESTS"):
        SafetyGate("staging").validate(scenario)

    monkeypatch.setenv("ALLOW_DESTRUCTIVE_TESTS", "true")
    monkeypatch.setenv("AIOPS_TEST_ALLOWED_TARGETS", "other-service")
    with pytest.raises(BlockedScenario, match="target_not_allowlisted"):
        SafetyGate("staging").validate(scenario)


def test_operational_artifacts_are_not_committed():
    gitignore = (Path(__file__).resolve().parents[2] / ".gitignore").read_text(encoding="utf-8")
    assert "artifacts/" in gitignore or "artifacts" in gitignore
