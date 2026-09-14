import json

import pytest

from agents.application import ApplicationAgent
from agents.database import DatabaseAgent
from agents.shared.base import AgentInput
from agents.shared.coordinator import IncidentCoordinator
from domain.contracts.config import settings
from integrations.llm.base import LLMAdapter, LLMResponse


class PostgresConnectionExhaustionScenarioLLM(LLMAdapter):
    """Deterministic INC-002 adapter that exercises normal parsing and safety contracts."""

    @property
    def provider_name(self):
        return "postgres-connection-exhaustion-acceptance"

    async def generate(self, prompt, system_prompt=None, temperature=0.7, max_tokens=1000, **kwargs):
        shared_hypothesis = "application connection leak exhausted PostgreSQL connection capacity"
        if "You are the database specialist" in prompt:
            payload = {
                "severity": "high",
                "health_status": "degraded",
                "findings": [
                    "PostgreSQL active connections reached configured capacity",
                    "server logs report reserved connection slots only",
                ],
                "affected_components": ["orders-postgres", "orders-api"],
                "probable_dependencies": ["orders-api connection pool"],
                "blast_radius": "orders requests requiring a database connection",
                "hypotheses": [{
                    "hypothesis": shared_hypothesis,
                    "probability": 0.92,
                    "evidence_ids": ["pg-connections-high", "pg-reserved-slots", "app-pool-waiters"],
                    "conflicting_evidence_ids": [],
                    "falsification_checks": [
                        "compare application pool checkout/return behavior with PostgreSQL session age and state"
                    ],
                    "impacted_components": ["orders-postgres", "orders-api"],
                    "recommended_next_evidence": [
                        "PostgreSQL pg_stat_activity grouped by application and state",
                        "application connection pool acquire/return metrics",
                    ],
                }],
                "missing_evidence": [],
                "handoff_agents": ["application", "infrastructure"],
                "immediate_checks": [
                    "Inspect PostgreSQL session counts, session age, state and application_name",
                    "Compare max_connections with active, idle and waiting sessions",
                ],
                "escalation_target": "database-sre",
                "risk_level": "high",
                "uncertainty_reason": "",
                "confidence": 0.92,
            }
        elif "senior SRE application analyst" in prompt:
            payload = {
                "severity": "high",
                "health_status": "degraded",
                "findings": [
                    "orders API is timing out while acquiring database connections",
                    "connection pool waiters increased with PostgreSQL saturation",
                ],
                "error_patterns": ["database connection acquire timeout"],
                "http_status_patterns": ["5xx during database-backed requests"],
                "latency_signals": ["connection acquire latency increased"],
                "exception_clusters": ["pool acquire timeout"],
                "endpoint_impacts": ["database-backed order endpoints"],
                "deployment_correlation": None,
                "config_drift_signals": [],
                "dependency_signals": ["orders-postgres connection saturation"],
                "probable_dependencies": ["orders-postgres"],
                "affected_components": ["orders-api", "orders-postgres"],
                "blast_radius": "orders requests requiring a database connection",
                "hypotheses": [{
                    "hypothesis": shared_hypothesis,
                    "probability": 0.86,
                    "evidence_ids": ["app-pool-timeout", "app-pool-waiters", "pg-connections-high"],
                    "conflicting_evidence_ids": [],
                    "falsification_checks": [
                        "verify whether pool borrowers return connections and whether long-lived sessions map to orders-api"
                    ],
                    "impacted_components": ["orders-api", "orders-postgres"],
                    "recommended_next_evidence": [
                        "connection pool borrowed/returned counters",
                        "PostgreSQL session ownership and age",
                    ],
                }],
                "missing_evidence": [],
                "handoff_agents": ["database"],
                "immediate_checks": [
                    "Inspect connection pool in-use, idle and waiting counts",
                    "Correlate acquire timeouts with request error rate and PostgreSQL sessions",
                ],
                "escalation_target": "application-sre",
                "risk_level": "high",
                "uncertainty_reason": "",
                "confidence": 0.86,
            }
        else:
            raise AssertionError(f"unexpected scenario prompt: {prompt[:160]}")
        return LLMResponse(content=json.dumps(payload), model="scenario")

    async def generate_with_messages(self, messages, temperature=0.7, max_tokens=1000, **kwargs):
        return await self.generate(messages[-1]["content"], temperature=temperature, max_tokens=max_tokens)


class UnsafeDatabaseRecommendationLLM(LLMAdapter):
    @property
    def provider_name(self):
        return "unsafe-database-recommendation"

    async def generate(self, prompt, system_prompt=None, temperature=0.7, max_tokens=1000, **kwargs):
        payload = {
            "severity": "high",
            "health_status": "degraded",
            "findings": ["PostgreSQL connection capacity is exhausted"],
            "affected_components": ["orders-postgres"],
            "probable_dependencies": ["orders-api"],
            "blast_radius": "orders database-backed requests",
            "hypotheses": [{
                "hypothesis": "PostgreSQL connection capacity is exhausted",
                "probability": 0.9,
                "evidence_ids": ["pg-connections-high", "pg-reserved-slots"],
                "conflicting_evidence_ids": [],
                "falsification_checks": ["inspect current sessions and configured max_connections"],
            }],
            "missing_evidence": [],
            "handoff_agents": ["application"],
            # Deliberately violates the read-only prompt. The common contract must reclassify it.
            "immediate_checks": ["Restart PostgreSQL"],
            "confidence": 0.9,
        }
        return LLMResponse(content=json.dumps(payload), model="scenario")

    async def generate_with_messages(self, messages, temperature=0.7, max_tokens=1000, **kwargs):
        return await self.generate(messages[-1]["content"], temperature=temperature, max_tokens=max_tokens)


def postgres_exhaustion_input():
    return AgentInput(
        incident_id="inc-postgres-connections-002",
        service_name="orders",
        evidence_summary="orders API cannot acquire database connections while PostgreSQL is at connection capacity",
        context={
            "evidence": [
                {
                    "id": "pg-connections-high",
                    "type": "metric",
                    "source": "prometheus",
                    "name": "postgres_active_connections_ratio",
                    "value": 1.0,
                },
                {
                    "id": "pg-reserved-slots",
                    "type": "log",
                    "source": "elasticsearch",
                    "message": "FATAL: remaining connection slots are reserved for non-replication superuser connections",
                },
                {
                    "id": "app-pool-timeout",
                    "type": "log",
                    "source": "elasticsearch",
                    "message": "orders-api database connection acquire timeout",
                },
                {
                    "id": "app-pool-waiters",
                    "type": "metric",
                    "source": "prometheus",
                    "name": "orders_db_pool_waiters",
                    "value": 48,
                },
            ]
        },
    )


def test_postgres_exhaustion_routes_database_then_application(monkeypatch):
    monkeypatch.setattr(settings, "AGENT_MAX_PARALLELISM", 6)
    monkeypatch.setattr(settings, "AGENT_LOW_CONFIDENCE_THRESHOLD", 0.5)

    routing = IncidentCoordinator.select_agents(
        {
            "handoff_agents": ["database", "application"],
            "analysis_details": {"primary_domain": "database"},
            "confidence": 0.95,
        },
        enabled=["database", "application", "storage", "infrastructure", "recovery", "dependency"],
    )

    assert routing["reason"] == "triage_specialist_routing"
    assert routing["primary_domain"] == "database"
    assert routing["selected"][:2] == ["database", "application"]


@pytest.mark.asyncio
async def test_postgres_exhaustion_multi_agent_analysis_is_grounded_and_reaches_consensus():
    adapter = PostgresConnectionExhaustionScenarioLLM()
    incident = postgres_exhaustion_input()

    database = await DatabaseAgent(adapter).analyze(incident)
    application = await ApplicationAgent(adapter).analyze(incident)

    live_ids = {
        "pg-connections-high",
        "pg-reserved-slots",
        "app-pool-timeout",
        "app-pool-waiters",
    }
    for result in (database, application):
        assert result.findings
        assert result.confidence > 0
        assert result.evidence_count == 4
        assert set(result.evidence_ids) == live_ids
        assert not result.missing_evidence
        assert result.requires_human_review == (
            result.confidence < settings.AGENT_LOW_CONFIDENCE_THRESHOLD
        )
        for hypothesis in result.hypotheses:
            assert set(hypothesis.evidence_ids).issubset(live_ids)
            assert hypothesis.falsification_checks
        assert all(action.read_only for action in result.recommended_actions)
        assert all(not action.requires_approval for action in result.recommended_actions)

    synthesis = IncidentCoordinator.synthesize([
        database.model_dump(mode="json"),
        application.model_dump(mode="json"),
    ])

    hypothesis = "application connection leak exhausted postgresql connection capacity"
    assert synthesis["disagreement"] is False
    assert synthesis["contradictions"] == []
    assert synthesis["requires_human_review"] is False
    assert synthesis["evidence_count"] == 4
    assert hypothesis in synthesis["consensus_hypotheses"]
    assert synthesis["consensus_support"][hypothesis] == ["application", "database"]


@pytest.mark.asyncio
async def test_database_agent_cannot_disguise_restart_as_read_only_investigation():
    result = await DatabaseAgent(UnsafeDatabaseRecommendationLLM()).analyze(postgres_exhaustion_input())

    assert len(result.recommended_actions) == 1
    recommendation = result.recommended_actions[0]
    assert recommendation.action == "Restart PostgreSQL"
    assert recommendation.read_only is False
    assert recommendation.requires_approval is True
    assert recommendation.risk_level == "high"
    assert recommendation.purpose == "untrusted_write_recommendation"
    assert recommendation.suggested_tool is None
