import pytest

from apps.orchestrator.signal_aware import SignalAwareE2EOrchestrator
from integrations.llm.base import LLMAdapter, LLMResponse


class CaptureLLM(LLMAdapter):
    def __init__(self):
        self.prompts = []

    @property
    def provider_name(self) -> str:
        return "capture"

    async def generate(
        self,
        prompt: str,
        system_prompt=None,
        temperature: float = 0.7,
        max_tokens: int = 1000,
        **kwargs,
    ) -> LLMResponse:
        self.prompts.append(prompt)
        return LLMResponse(
            content="RCA based on live evidence with historical context revalidated.",
            model="test",
            finish_reason="stop",
        )

    async def generate_with_messages(self, messages, **kwargs):
        raise NotImplementedError


def _state():
    cited_id = "11111111-1111-1111-1111-111111111111"
    uncited_id = "22222222-2222-2222-2222-222222222222"
    return {
        "incident_id": "33333333-3333-3333-3333-333333333333",
        "service_name": "nginx",
        "evidence_summary": "nginx inactive and port unavailable",
        "context": {
            "evidence": [
                {
                    "id": "live-1",
                    "type": "metric",
                    "source": "prometheus",
                    "raw_data": {"service": "nginx", "status": "down"},
                }
            ],
            "knowledge_results": [
                {
                    "id": "knowledge-1",
                    "title": "nginx recovery runbook",
                    "content": "Validate service state before governed recovery.",
                }
            ],
            "knowledge_status": {"provider": "cognia", "status": "available"},
            "memory_results": [
                {
                    "id": cited_id,
                    "service_scope": "nginx",
                    "incident_pattern": {
                        "summary": "nginx inactive",
                        "observed_faults": ["service_active=false"],
                    },
                    "investigation": {
                        "investigation_summary": "Prior investigation found service inactive.",
                        "rca_synthesis": "Historical stop cause remained unconfirmed.",
                    },
                    "actual_remediation": {
                        "tool_name": "ssh_vm",
                        "action": "start_service",
                        "target": "10.0.0.10",
                        "parameters": {"password": "must-never-reach-rca"},
                        "execution_success": True,
                    },
                    "verification": {
                        "status": "success",
                        "recovered_signals": ["service_active"],
                    },
                    "memory_outcome_class": "successful_recovery",
                    "reusable_lesson": "Revalidate current state before reuse.",
                },
                {
                    "id": uncited_id,
                    "service_scope": "nginx",
                    "incident_pattern": {"summary": "different historical incident"},
                    "investigation": {
                        "rca_synthesis": "UNCITED-MEMORY-MUST-NOT-REACH-RCA"
                    },
                    "actual_remediation": {"action": "restart_service"},
                    "verification": {"status": "success"},
                    "memory_outcome_class": "successful_recovery",
                },
            ],
        },
        "triage_result": {
            "agent_name": "triage",
            "statement": "Current live evidence shows nginx unhealthy.",
            "confidence": 0.8,
            "historical_memory_ids": [],
        },
        "analysis_results": [
            {
                "agent_name": "vm",
                "statement": "Live evidence confirms nginx inactive.",
                "confidence": 0.9,
                "evidence_ids": ["live-1"],
                "historical_memory_ids": [cited_id],
            }
        ],
        "findings": [
            {
                "agent_name": "triage",
                "statement": "Current live evidence shows nginx unhealthy.",
                "confidence": 0.8,
                "historical_memory_ids": [],
            },
            {
                "agent_name": "vm",
                "statement": "Live evidence confirms nginx inactive.",
                "confidence": 0.9,
                "evidence_ids": ["live-1"],
                "historical_memory_ids": [cited_id],
            },
        ],
        "coordination": {
            "confidence": 0.85,
            "contradictions": [],
            "missing_evidence": ["historical stop actor"],
        },
    }


def test_rca_auxiliary_context_contains_only_agent_cited_memory():
    orchestrator = SignalAwareE2EOrchestrator.__new__(SignalAwareE2EOrchestrator)
    state = _state()

    auxiliary = orchestrator._rca_auxiliary_context(state)

    cited = auxiliary["cited_historical_memory"]
    assert len(cited) == 1
    assert cited[0]["id"] == "11111111-1111-1111-1111-111111111111"
    assert auxiliary["cited_memory_ids"] == [
        "11111111-1111-1111-1111-111111111111"
    ]
    assert "22222222-2222-2222-2222-222222222222" not in str(auxiliary)
    assert "must-never-reach-rca" not in str(auxiliary)
    assert "Historical stop cause remained unconfirmed." in str(auxiliary)


@pytest.mark.asyncio
async def test_rca_prompt_receives_bounded_cited_history_but_not_uncited_memory(monkeypatch):
    llm = CaptureLLM()
    orchestrator = SignalAwareE2EOrchestrator.__new__(SignalAwareE2EOrchestrator)
    orchestrator.llm = llm
    state = _state()

    monkeypatch.setattr(
        SignalAwareE2EOrchestrator,
        "_audit",
        staticmethod(lambda *args, **kwargs: None),
    )

    result = await orchestrator._rca_node(state)

    assert result["final_plan"].startswith("RCA based on live evidence")
    prompt = llm.prompts[0]
    assert "11111111-1111-1111-1111-111111111111" in prompt
    assert "Historical stop cause remained unconfirmed." in prompt
    assert "22222222-2222-2222-2222-222222222222" not in prompt
    assert "UNCITED-MEMORY-MUST-NOT-REACH-RCA" not in prompt
    assert "must-never-reach-rca" not in prompt
    assert "LIVE EVIDENCE wins" in prompt
