import json

import pytest

from agents.shared.base import AgentInput
from agents.triage import TriageAgent
from apps.context_service.asset_identity import AssetIdentityResolver
from domain.contracts.config import settings
from integrations.llm.base import LLMAdapter, LLMResponse


class NetworkRoutingScenarioLLM(LLMAdapter):
    @property
    def provider_name(self):
        return "network-routing-scenario"

    async def generate(self, prompt, system_prompt=None, temperature=0.7, max_tokens=1000, **kwargs):
        # Deliberately return an application-only diagnosis. Live asset identity
        # must still force the network cross-layer investigation wave.
        payload = {
            "primary_domain": "application",
            "secondary_domains": [],
            "severity": "high",
            "health_status": "degraded",
            "urgency_reason": "payment API probes time out",
            "findings": ["application timeout observed"],
            "affected_components": ["payments-api"],
            "probable_dependencies": [],
            "blast_radius": "payment path",
            "hypotheses": [],
            "missing_evidence": [],
            "specialist_routes": ["application"],
            "immediate_checks": ["inspect reachability metrics"],
            "escalation_target": "incident-commander",
            "risk_level": "medium",
            "uncertainty_reason": "",
            "confidence": 0.8,
        }
        return LLMResponse(content=json.dumps(payload), model="network-routing-scenario")

    async def generate_with_messages(self, messages, temperature=0.7, max_tokens=1000, **kwargs):
        return await self.generate(messages[-1]["content"])


@pytest.mark.asyncio
async def test_zabbix_network_device_identity_forces_network_cross_layer_triage(monkeypatch):
    monkeypatch.setattr(
        settings,
        "AGENT_ENABLED_AGENTS",
        ["application", "network", "infrastructure", "dependency"],
    )
    monkeypatch.setattr(settings, "AGENT_MAX_PARALLELISM", 4)
    monkeypatch.setattr(settings, "AGENT_MIN_EVIDENCE_ITEMS", 1)
    monkeypatch.setattr(settings, "AGENT_MIN_EVIDENCE_COVERAGE", 0.0)

    zabbix_evidence = {
        "id": "net-zbx-1",
        "reference": "net-zbx-1",
        "type": "metric",
        "source": "zabbix",
        "raw_data": {
            "host": {
                "hostid": "9001",
                "host": "edge-router-01",
                "groups": [{"name": "Production Network Devices"}],
                "parentTemplates": [{"name": "Cisco IOS by SNMP"}],
                "interfaces": [{"ip": "10.20.0.1"}],
                "tags": [{"tag": "environment", "value": "prod"}],
            },
            "value": 100,
        },
    }
    asset = AssetIdentityResolver.resolve([zabbix_evidence], service_hint="payments-api")

    assert asset["asset_type"] == "network"
    assert asset["hostname"] == "edge-router-01"
    assert asset["ip_addresses"] == ["10.20.0.1"]

    result = await TriageAgent(NetworkRoutingScenarioLLM()).analyze(
        AgentInput(
            incident_id="inc-network-timeout-001",
            service_name="payments-api",
            evidence_summary="Payment API requests time out while the edge network device is alerting",
            context={
                "evidence": [zabbix_evidence],
                "live_evidence": {
                    "evidence": [zabbix_evidence],
                    "asset_context": asset,
                },
                "asset_context": asset,
            },
        )
    )

    assert result.analysis_details["primary_domain"] == "network"
    assert result.analysis_details["asset_routing"] == [
        "network",
        "infrastructure",
        "dependency",
    ]
    assert result.handoff_agents[:3] == [
        "network",
        "infrastructure",
        "dependency",
    ]
