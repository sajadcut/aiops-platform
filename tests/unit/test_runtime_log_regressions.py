from __future__ import annotations

from datetime import datetime, timezone

import pytest

from agents.shared.coordinator import IncidentCoordinator
from apps.context_service.asset_identity import AssetIdentityResolver
from apps.context_service.evidence_collector import EvidenceCollector
from domain.contracts.config import settings
from integrations.llm.base import LLMResponse
from integrations.llm.openai_compatible import OpenAICompatibleLLMProvider


class SequenceProvider(OpenAICompatibleLLMProvider):
    def __init__(self, responses):
        super().__init__("http://unused.test", "test-model")
        self.responses = list(responses)
        self.calls = []

    async def generate_with_messages(self, messages, temperature=0.7, max_tokens=1000, **kwargs):
        self.calls.append({
            "messages": [dict(message) for message in messages],
            "max_tokens": max_tokens,
            "temperature": temperature,
        })
        return self.responses.pop(0)


class UnavailableConnector:
    async def health_check(self):
        return False


def _response(content: str, finish_reason: str) -> LLMResponse:
    return LLMResponse(content=content, model="test-model", finish_reason=finish_reason)


@pytest.mark.asyncio
async def test_shared_llm_generate_repairs_truncated_completion(monkeypatch):
    monkeypatch.setattr(settings, "AGENT_STRUCTURED_REPAIR_ATTEMPTS", 1)
    provider = SequenceProvider([
        _response("partial RCA", "length"),
        _response("complete RCA", "stop"),
    ])

    result = await provider.generate("analyze incident", max_tokens=100)

    assert result.content == "complete RCA"
    assert [call["max_tokens"] for call in provider.calls] == [100, 200]
    assert len(provider.calls[1]["messages"]) == 2
    assert "previous response was truncated" in provider.calls[1]["messages"][-1]["content"]


@pytest.mark.asyncio
async def test_shared_llm_generate_fails_closed_after_truncation_budget(monkeypatch):
    monkeypatch.setattr(settings, "AGENT_STRUCTURED_REPAIR_ATTEMPTS", 1)
    provider = SequenceProvider([
        _response("partial one", "length"),
        _response("partial two", "max_tokens"),
    ])

    with pytest.raises(ValueError, match="llm_completion_truncated_after_retries"):
        await provider.generate("analyze incident", max_tokens=100)


def test_source_observations_do_not_promote_asset_identity_or_source_confidence():
    evidence = [
        {
            "type": "alert",
            "source": "zabbix",
            "reference": "EVENT-1",
            "raw_data": {"host": {"hostid": "42", "host": "app-01"}},
        },
        {
            "type": "source_observation",
            "source": "elasticsearch",
            "reference": "elastic-unavailable",
            "raw_data": {"status": "unavailable", "service": "payments"},
        },
        {
            "type": "source_observation",
            "source": "prometheus",
            "reference": "prom-unavailable",
            "raw_data": {"status": "unavailable", "service": "payments"},
        },
    ]

    asset = AssetIdentityResolver.resolve(evidence, "payments")

    assert asset["source_refs"] == ["EVENT-1"]
    assert asset["source_confidence"] == {"zabbix": 1.0}
    assert asset["hostname"] == "app-01"


def test_identical_support_and_conflict_agent_sets_do_not_create_false_disagreement(monkeypatch):
    monkeypatch.setattr(settings, "AGENT_CONFLICT_CONFIDENCE_PENALTY", 0.2)
    monkeypatch.setattr(settings, "AGENT_DISAGREEMENT_CONFIDENCE_FACTOR", 0.75)
    monkeypatch.setattr(settings, "AGENT_MISSING_EVIDENCE_CONFIDENCE_FACTOR", 0.85)
    findings = []
    for agent in ("network", "application"):
        findings.append({
            "agent_name": agent,
            "severity": "medium",
            "health_status": "degraded",
            "confidence": 0.7,
            "evidence_coverage": 1.0,
            "evidence_ids": ["EVENT-1"],
            "hypotheses": [
                {
                    "hypothesis": "firewall blocks the service",
                    "evidence_ids": ["EVENT-1"],
                    "conflicting_evidence_ids": [],
                },
                {
                    "hypothesis": "monitoring false positive",
                    "evidence_ids": [],
                    "conflicting_evidence_ids": ["EVENT-1"],
                },
            ],
            "missing_evidence": [],
            "handoff_agents": [],
            "evidence_requests": [],
        })

    result = IncidentCoordinator.synthesize(findings)

    assert result["disagreement"] is False
    assert not any("support_only_agents" in row for row in result["contradictions"])
    assert result["requires_human_review"] is True


@pytest.mark.asyncio
async def test_requested_round_keeps_unavailable_status_but_returns_no_new_evidence():
    collector = EvidenceCollector(
        elasticsearch=UnavailableConnector(),
        prometheus=UnavailableConnector(),
    )

    result = await collector.collect_requested(
        "payments",
        datetime.now(timezone.utc),
        [{"evidence_type": "log"}, {"evidence_type": "metric"}],
    )

    assert result["evidence"] == []
    assert len(result["source_observations"]) == 2
    assert {item["raw_data"]["status"] for item in result["source_observations"]} == {"unavailable"}
    assert {item["source"] for item in result["source_observations"]} == {"elasticsearch", "prometheus"}
