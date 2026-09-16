import json

import pytest

from agents.database import DatabaseAgent
from agents.identity import IdentityAgent
from agents.shared.base import AgentInput
from agents.shared.intelligence import (
    build_deterministic_analysis,
    prompt_evidence_projection,
    sanitize_prompt_value,
)
from integrations.llm.base import LLMAdapter, LLMResponse


class StaticLLM(LLMAdapter):
    def __init__(self, payload):
        self.payload = payload
        self.prompts = []

    @property
    def provider_name(self) -> str:
        return "static-test"

    async def generate(self, prompt, system_prompt=None, temperature=0.7, max_tokens=1000, **kwargs):
        self.prompts.append(prompt)
        return LLMResponse(content=json.dumps(self.payload), model="static-test")

    async def generate_with_messages(self, messages, temperature=0.7, max_tokens=1000, **kwargs):
        return await self.generate(messages[-1]["content"], temperature=temperature, max_tokens=max_tokens)


def test_prompt_sanitization_redacts_credentials_and_bearer_tokens():
    raw = {
        "authorization": "Bearer super-secret-token",
        "nested": {"access_token": "abc123", "safe": "Bearer another-secret"},
        "password": "hunter2",
    }
    safe = sanitize_prompt_value(raw)
    encoded = json.dumps(safe)
    assert "super-secret-token" not in encoded
    assert "another-secret" not in encoded
    assert "abc123" not in encoded
    assert "hunter2" not in encoded
    assert encoded.count("[REDACTED]") >= 3


def test_application_intelligence_extracts_timeline_baseline_and_database_handoff():
    evidence = [
        {
            "id": "m1", "type": "metric", "source": "prometheus", "timestamp": "2026-09-16T10:00:00Z",
            "name": "http_5xx_rate", "value": 0.12, "raw_data": {"baseline": 0.01},
        },
        {
            "id": "l1", "type": "log", "source": "elasticsearch", "timestamp": "2026-09-16T10:01:00Z",
            "message": "connection pool timeout talking to database",
        },
    ]
    analysis = build_deterministic_analysis("application", evidence, ["metric", "log"], "payments-api")
    assert analysis["evidence_gap_matrix"]["metric"]["present"] is True
    assert analysis["evidence_gap_matrix"]["log"]["present"] is True
    assert analysis["timeline"][0]["evidence_id"] == "m1"
    assert analysis["metric_features"]["largest_baseline_deltas"][0]["metric"] == "http_5xx_rate"
    assert any(item["agent"] == "database" for item in analysis["suggested_handoffs"])


def test_kubernetes_intelligence_indexes_resource_evidence_without_declaring_root_cause():
    evidence = [
        {"id": "e1", "type": "event", "source": "kubernetes", "message": "Pod checkout CrashLoopBackOff"},
        {"id": "e2", "type": "event", "source": "kubernetes", "message": "PVC data Pending mount"},
    ]
    analysis = build_deterministic_analysis("kubernetes", evidence, ["event"], "checkout")
    assert analysis["resource_evidence_counts"]["pod"] >= 1
    assert analysis["resource_evidence_counts"]["pvc"] >= 1
    assert "root_cause" not in analysis
    assert analysis["policy"].startswith("deterministic_features_are_observations")


def test_recovery_intelligence_distinguishes_latest_from_verified_restore_point():
    evidence = [
        {
            "id": "b-new", "type": "log", "source": "backup", "message": "backup succeeded",
            "raw_data": {"backup_time": "2026-09-16T09:00:00Z", "verified": False},
        },
        {
            "id": "b-old", "type": "log", "source": "backup", "message": "restore test succeeded",
            "raw_data": {"backup_time": "2026-09-16T07:00:00Z", "restore_verified": True},
        },
    ]
    analysis = build_deterministic_analysis("recovery", evidence, ["log"])
    points = analysis["recovery_points"]
    assert points["latest_restore_or_backup_evidence_id"] == "b-new"
    assert points["latest_verified_restore_evidence_id"] == "b-old"
    assert points["restore_validation_missing"] is False


def test_prompt_projection_does_not_leak_identity_tokens():
    projected = prompt_evidence_projection([
        {
            "id": "auth-1", "type": "log", "source": "identity", "message": "401 token rejected",
            "raw_data": {"authorization": "Bearer do-not-leak", "access_token": "secret-value", "issuer": "https://idp.example"},
        }
    ])
    encoded = json.dumps(projected)
    assert "do-not-leak" not in encoded
    assert "secret-value" not in encoded
    assert "https://idp.example" in encoded


@pytest.mark.asyncio
async def test_generic_database_agent_exposes_deterministic_analysis_and_handoff():
    llm = StaticLLM({
        "severity": "high", "health_status": "degraded",
        "findings": ["connection pressure observed"],
        "affected_components": ["postgres"], "probable_dependencies": ["payments-api"],
        "blast_radius": "single database", "hypotheses": [], "missing_evidence": [],
        "handoff_agents": [], "immediate_checks": ["Inspect normalized query and wait metrics"],
        "confidence": 0.75,
    })
    input_data = AgentInput(
        incident_id="db-1", service_name="postgres", evidence_summary="connection pressure",
        context={"evidence": [
            {"id": "m1", "type": "metric", "source": "prometheus", "name": "connections", "value": 95},
            {"id": "l1", "type": "log", "source": "elasticsearch", "message": "application connection storm and slow query"},
        ]},
    )
    result = await DatabaseAgent(llm).analyze(input_data)
    assert result.analysis_details["deterministic_analysis"]["domain"] == "database"
    assert result.analysis_details["next_best_evidence"]
    assert "application" in result.handoff_agents
    assert "DETERMINISTIC_ANALYSIS=" in llm.prompts[0]


@pytest.mark.asyncio
async def test_identity_agent_redacts_sensitive_evidence_before_llm():
    llm = StaticLLM({
        "severity": "medium", "health_status": "degraded", "findings": ["token validation failed"],
        "affected_components": ["login"], "blast_radius": "single service", "hypotheses": [],
        "missing_evidence": [], "handoff_agents": [], "immediate_checks": ["Inspect JWKS reachability"],
        "confidence": 0.6,
    })
    input_data = AgentInput(
        incident_id="id-1", service_name="login", evidence_summary="token failure",
        context={"evidence": [
            {
                "id": "l1", "type": "log", "source": "elasticsearch", "message": "JWKS key not found",
                "raw_data": {"authorization": "Bearer secret-token", "client_secret": "top-secret"},
            }
        ]},
    )
    await IdentityAgent(llm).analyze(input_data)
    prompt = llm.prompts[0]
    assert "secret-token" not in prompt
    assert "top-secret" not in prompt
    assert "[REDACTED]" in prompt
