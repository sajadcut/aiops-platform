import json

import pytest

from agents.shared.base import AgentInput
from agents.shared.coordinator import IncidentCoordinator
from agents.triage import TriageAgent
from agents.triage.engine import build_triage_decision_support
from domain.contracts.config import settings
from integrations.llm.base import LLMAdapter, LLMResponse


class StaticTriageLLM(LLMAdapter):
    def __init__(self, primary="application", confidence=0.9):
        self.primary = primary
        self.confidence = confidence

    @property
    def provider_name(self):
        return "static-triage"

    async def generate(self, prompt, system_prompt=None, temperature=0.7, max_tokens=1000, **kwargs):
        payload = {
            "primary_domain": self.primary,
            "secondary_domains": [],
            "severity": "critical",
            "health_status": "degraded",
            "urgency_reason": "model supplied",
            "findings": ["model synthesis"],
            "affected_components": [],
            "probable_dependencies": [],
            "blast_radius": "model supplied",
            "hypotheses": [],
            "missing_evidence": [],
            "evidence_gaps": [],
            "next_best_evidence": [],
            "specialist_routes": [self.primary],
            "route_reasons": [],
            "rejected_routes": [],
            "immediate_checks": ["Inspect live evidence"],
            "escalation_target": "incident-commander",
            "risk_level": "low",
            "uncertainty_reason": "",
            "confidence": self.confidence,
        }
        return LLMResponse(content=json.dumps(payload), model="static-triage")

    async def generate_with_messages(self, messages, temperature=0.7, max_tokens=1000, **kwargs):
        return await self.generate(messages[-1]["content"], temperature=temperature, max_tokens=max_tokens)


def decision(evidence, *, asset=None, topology=None, context=None, enabled=None, stale_ids=None, max_routes=6):
    return build_triage_decision_support(
        fresh_evidence=evidence,
        raw_evidence=evidence,
        stale_ids=stale_ids or [],
        asset=asset or {},
        topology=topology or {},
        context=context or {},
        enabled_domains=enabled or [
            "application", "infrastructure", "kubernetes", "security", "vm",
            "database", "network", "storage", "identity", "change", "dependency",
            "messaging", "recovery",
        ],
        max_routes=max_routes,
    )


def test_500_symptom_routes_to_database_when_connection_exhaustion_is_evidenced():
    result = decision([
        {"id": "app-500", "type": "log", "source": "elasticsearch", "message": "HTTP 500 timeout while acquiring database connection"},
        {"id": "db-full", "type": "log", "source": "elasticsearch", "message": "PostgreSQL FATAL too many connections connection exhaustion"},
        {"id": "db-metric", "type": "metric", "source": "prometheus", "name": "postgres_active_connections", "message": "database connections at capacity"},
    ], asset={"asset_type": "application", "confidence": 1.0})

    assert result["primary_domain"] == "database"
    assert "application" in result["secondary_domains"]
    assert result["specialist_routes"][0] == "database"
    assert result["causal_matches"][0]["symptom_domain"] == "application"


def test_vm_service_down_routes_to_network_when_path_failure_is_evidenced():
    result = decision([
        {"id": "svc", "type": "telemetry", "source": "vm_mcp", "message": "systemd service failed and listener absent"},
        {"id": "path", "type": "metric", "source": "prometheus", "message": "network path unreachable tcp connection timed out"},
    ], asset={"asset_type": "vm", "platform": "vm", "os_family": "linux", "confidence": 1.0})

    assert result["primary_domain"] == "network"
    assert "vm" in result["secondary_domains"]
    assert result["specialist_routes"][0] == "network"


def test_kubernetes_pod_failure_routes_to_storage_when_pvc_is_causal_signal():
    result = decision([
        {"id": "pod", "type": "event", "source": "kubernetes_api", "message": "Pod pending FailedMount PVC volume mount failed"},
        {"id": "pvc", "type": "telemetry", "source": "kubernetes_api", "message": "PVC storage volume unavailable"},
    ], asset={"asset_type": "kubernetes_workload", "platform": "kubernetes", "confidence": 1.0})

    assert result["primary_domain"] == "storage"
    assert "kubernetes" in result["secondary_domains"]
    assert result["specialist_routes"][0] == "storage"


def test_duplicate_alerts_across_hosts_form_one_correlation_group_without_losing_evidence():
    evidence = [
        {"id": f"a{i}", "type": "alert", "source": "zabbix", "message": "checkout service unavailable", "raw_data": {"host": f"web-{i}", "service": "checkout"}}
        for i in range(1, 4)
    ]
    result = decision(evidence)

    storms = result["alert_storm_groups"]
    assert len(storms) == 1
    assert storms[0]["count"] == 3
    assert storms[0]["hosts"] == ["web-1", "web-2", "web-3"]
    assert storms[0]["evidence_ids"] == ["a1", "a2", "a3"]
    assert storms[0]["individual_evidence_preserved"] is True
    assert result["alert_storm_not_incident_storm"] is True


def test_critical_alert_is_not_critical_without_customer_impact_and_with_healthy_redundancy():
    result = decision([
        {"id": "alert-1", "type": "alert", "source": "zabbix", "severity": "critical", "message": "latency threshold exceeded"},
    ], context={"summary": {"customer_impact": False, "redundancy": "healthy", "affected_services": 1}})

    assert result["severity"] in {"low", "medium"}
    assert result["severity"] not in {"high", "critical"}
    assert result["severity_details"]["customer_impact_explicitly_absent"] is True


def test_topology_conflict_is_explicit_and_reduces_routing_confidence():
    result = decision([
        {"id": "m1", "type": "metric", "source": "prometheus", "message": "HTTP 500 latency"},
    ], asset={
        "asset_type": "vm",
        "platform": "vm",
        "confidence": 0.8,
        "topology_conflicts": [{"field": "platform", "live": "vm", "knowledge": "kubernetes"}],
    })

    assert result["topology_conflicts"]
    assert result["routing_confidence_band"] == "low"
    assert any(gap["domain"] == "topology" for gap in result["evidence_gap_matrix"])


def test_unknown_asset_requests_identity_verification_before_confident_routing():
    result = decision([
        {"id": "a1", "type": "alert", "source": "zabbix", "message": "service timeout"},
    ], asset={"asset_type": "unknown", "platform": "unknown", "confidence": 0.1})

    assert result["unknown_asset"] is True
    assert result["routing_confidence"] <= 0.45
    assert any(gap["domain"] == "asset_identity" for gap in result["evidence_gap_matrix"])
    assert any(item["domain"] == "asset_identity" for item in result["next_best_evidence"])


def test_insufficient_evidence_produces_low_confidence_bounded_investigation():
    result = decision([], asset={}, enabled=["application", "database", "network", "storage"], max_routes=3)

    assert result["primary_domain"] == "unknown"
    assert result["routing_confidence_band"] == "low"
    assert len(result["specialist_routes"]) == 3
    assert result["unknown_asset"] is True


@pytest.mark.asyncio
async def test_stale_alert_is_explicit_and_fresh_replacement_is_requested(monkeypatch):
    monkeypatch.setattr(settings, "AGENT_ENABLED_AGENTS", ["application", "database", "network"])
    monkeypatch.setattr(settings, "AGENT_MIN_EVIDENCE_ITEMS", 1)
    incident = AgentInput(
        incident_id="stale-1",
        service_name="checkout",
        evidence_summary="old critical alert",
        context={
            "asset_context": {"asset_type": "unknown", "platform": "unknown", "confidence": 0.0},
            "evidence": [
                {"id": "old-alert", "type": "alert", "source": "zabbix", "timestamp": "2025-01-01T00:00:00Z", "severity": "critical", "message": "HTTP 500"},
            ],
        },
    )

    result = await TriageAgent(StaticTriageLLM()).analyze(incident)

    assert result.analysis_details["stale_evidence_ids"] == ["old-alert"]
    assert result.analysis_details["stale_evidence_count"] == 1
    assert "fresh evidence replacing stale observations" in result.missing_evidence
    assert result.confidence <= settings.AGENT_LOW_CONFIDENCE_THRESHOLD


def test_coordinator_uses_new_confidence_band_for_adaptive_fanout(monkeypatch):
    monkeypatch.setattr(settings, "AGENT_MAX_PARALLELISM", 5)
    enabled = ["application", "database", "network", "storage", "dependency"]

    high = IncidentCoordinator.select_agents({
        "confidence": 0.9,
        "handoff_agents": ["database", "application", "storage"],
        "analysis_details": {
            "primary_domain": "database",
            "specialist_routes": ["database", "application"],
            "routing_confidence_band": "high",
        },
    }, enabled)
    assert high["reason"] == "triage_focused_routing"
    assert high["selected"] == ["database", "application"]

    medium = IncidentCoordinator.select_agents({
        "confidence": 0.65,
        "handoff_agents": ["database", "application", "storage"],
        "analysis_details": {
            "primary_domain": "database",
            "specialist_routes": ["database", "application"],
            "routing_confidence_band": "medium",
        },
    }, enabled)
    assert medium["reason"] == "triage_primary_secondary_routing"
    assert medium["selected"][:2] == ["database", "application"]
    assert len(medium["selected"]) <= 3

    low = IncidentCoordinator.select_agents({
        "confidence": 0.3,
        "handoff_agents": ["database"],
        "analysis_details": {
            "primary_domain": "database",
            "specialist_routes": ["database"],
            "routing_confidence_band": "low",
            "topology_conflict_count": 1,
        },
    }, enabled)
    assert low["reason"] == "fallback_broad_analysis"
    assert len(low["selected"]) == 5
