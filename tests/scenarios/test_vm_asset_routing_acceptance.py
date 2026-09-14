import json

import pytest

from agents.shared.base import AgentInput
from agents.triage import TriageAgent
from domain.contracts.config import settings
from integrations.llm.base import LLMAdapter, LLMResponse


class VMTriageScenarioLLM(LLMAdapter):
    @property
    def provider_name(self):
        return "vm-triage-acceptance"

    async def generate(self, prompt, system_prompt=None, temperature=0.7, max_tokens=1000, **kwargs):
        payload = {
            "primary_domain": "vm",
            "secondary_domains": [],
            "severity": "critical",
            "health_status": "unhealthy",
            "urgency_reason": "service is unavailable and endpoint checks are timing out",
            "findings": ["payments-api service is inactive", "endpoint probes time out"],
            "affected_components": ["payments-vm-01", "payments-api"],
            "probable_dependencies": ["network-path"],
            "blast_radius": "payments API requests",
            "hypotheses": [{
                "hypothesis": "guest service failure or network path failure",
                "probability": 0.82,
                "evidence_ids": ["vm-service-inactive", "endpoint-timeout"],
                "conflicting_evidence_ids": [],
                "falsification_checks": ["check service state and network reachability independently"],
                "impacted_components": ["payments-vm-01", "payments-api"],
                "recommended_next_evidence": ["network path and DNS evidence"],
            }],
            "missing_evidence": [],
            "specialist_routes": [],
            "immediate_checks": ["Inspect service state, VM telemetry and network reachability"],
            "escalation_target": "infrastructure-sre",
            "risk_level": "high",
            "uncertainty_reason": "",
            "confidence": 0.88,
        }
        return LLMResponse(content=json.dumps(payload), model="scenario")

    async def generate_with_messages(self, messages, temperature=0.7, max_tokens=1000, **kwargs):
        return await self.generate(messages[-1]["content"], temperature=temperature, max_tokens=max_tokens)


@pytest.mark.asyncio
async def test_vm_asset_routes_network_specialist_in_first_wave(monkeypatch):
    monkeypatch.setattr(
        settings,
        "AGENT_ENABLED_AGENTS",
        ["vm", "infrastructure", "network", "application", "dependency", "recovery"],
    )
    monkeypatch.setattr(settings, "AGENT_MAX_PARALLELISM", 6)

    incident = AgentInput(
        incident_id="inc-vm-service-down-003",
        service_name="payments-api",
        evidence_summary="VM-hosted payments service is inactive and endpoint checks time out",
        context={
            "asset_context": {
                "asset_type": "vm",
                "platform": "vm",
                "os_family": "linux",
                "confidence": 1.0,
            },
            "evidence": [
                {
                    "id": "vm-service-inactive",
                    "type": "log",
                    "source": "vm_telemetry",
                    "message": "payments-api.service inactive (dead)",
                },
                {
                    "id": "endpoint-timeout",
                    "type": "metric",
                    "source": "prometheus",
                    "name": "probe_success",
                    "value": 0,
                },
            ],
        },
    )

    result = await TriageAgent(VMTriageScenarioLLM()).analyze(incident)

    assert result.analysis_details["primary_domain"] == "vm"
    assert result.analysis_details["asset_routing"] == [
        "vm",
        "infrastructure",
        "network",
    ]
    assert result.handoff_agents[:3] == [
        "vm",
        "infrastructure",
        "network",
    ]
