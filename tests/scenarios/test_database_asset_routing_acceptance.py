import json

import pytest

from agents.shared.base import AgentInput
from agents.triage import TriageAgent
from domain.contracts.config import settings
from integrations.llm.base import LLMAdapter, LLMResponse


class DatabaseTriageScenarioLLM(LLMAdapter):
    @property
    def provider_name(self):
        return "database-triage-acceptance"

    async def generate(self, prompt, system_prompt=None, temperature=0.7, max_tokens=1000, **kwargs):
        payload = {
            "primary_domain": "database",
            "secondary_domains": [],
            "severity": "high",
            "health_status": "degraded",
            "urgency_reason": "database connection capacity is exhausted",
            "findings": ["PostgreSQL is at connection capacity"],
            "affected_components": ["orders-postgres", "orders-api"],
            "probable_dependencies": ["orders-api"],
            "blast_radius": "database-backed order requests",
            "hypotheses": [{
                "hypothesis": "database connection exhaustion",
                "probability": 0.9,
                "evidence_ids": ["pg-connections-high", "pg-reserved-slots"],
                "conflicting_evidence_ids": [],
                "falsification_checks": ["inspect session ownership and pool behavior"],
                "impacted_components": ["orders-postgres", "orders-api"],
                "recommended_next_evidence": ["application pool metrics"],
            }],
            "missing_evidence": [],
            "specialist_routes": [],
            "immediate_checks": ["Inspect database sessions and application pool metrics"],
            "escalation_target": "database-sre",
            "risk_level": "high",
            "uncertainty_reason": "",
            "confidence": 0.9,
        }
        return LLMResponse(content=json.dumps(payload), model="scenario")

    async def generate_with_messages(self, messages, temperature=0.7, max_tokens=1000, **kwargs):
        return await self.generate(messages[-1]["content"], temperature=temperature, max_tokens=max_tokens)


@pytest.mark.asyncio
async def test_database_asset_routes_cross_layer_specialists_early(monkeypatch):
    monkeypatch.setattr(
        settings,
        "AGENT_ENABLED_AGENTS",
        ["database", "application", "dependency", "infrastructure", "storage", "recovery"],
    )
    monkeypatch.setattr(settings, "AGENT_MAX_PARALLELISM", 6)

    incident = AgentInput(
        incident_id="inc-postgres-routing-002",
        service_name="orders",
        evidence_summary="PostgreSQL connection exhaustion affects orders API",
        context={
            "asset_context": {
                "asset_type": "database",
                "platform": "postgresql",
                "confidence": 1.0,
            },
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
                    "message": "remaining connection slots are reserved",
                },
            ],
        },
    )

    result = await TriageAgent(DatabaseTriageScenarioLLM()).analyze(incident)

    assert result.analysis_details["primary_domain"] == "database"
    assert result.analysis_details["asset_routing"] == [
        "database",
        "application",
        "dependency",
        "infrastructure",
    ]
    assert result.handoff_agents[:4] == [
        "database",
        "application",
        "dependency",
        "infrastructure",
    ]
