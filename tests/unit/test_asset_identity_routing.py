import json

import pytest

from agents.shared.base import AgentInput
from agents.triage import TriageAgent
from apps.context_service.asset_identity import AssetIdentityResolver
from domain.contracts.config import settings
from integrations.llm.base import LLMAdapter, LLMResponse


class StaticLLM(LLMAdapter):
    def __init__(self, payload):
        self.payload = payload

    @property
    def provider_name(self):
        return "static"

    async def generate(self, prompt, system_prompt=None, temperature=0.7, max_tokens=1000, **kwargs):
        return LLMResponse(content=json.dumps(self.payload), model="static")

    async def generate_with_messages(self, messages, temperature=0.7, max_tokens=1000, **kwargs):
        return await self.generate(messages[-1]["content"])


def test_zabbix_inventory_identifies_windows_vm():
    evidence = [{
        "type": "alert", "source": "zabbix", "reference": "z1",
        "raw_data": {
            "host": {
                "hostid": "42", "host": "pay-win-01",
                "inventory": {"os_full": "Microsoft Windows Server 2022"},
                "groups": [{"name": "Production VMs"}],
                "parentTemplates": [{"name": "Windows by Zabbix agent"}],
                "interfaces": [{"ip": "10.1.2.3"}],
                "tags": [{"tag": "environment", "value": "prod"}, {"tag": "service", "value": "payments"}],
            },
            "tags": [{"tag": "asset_type", "value": "vm"}],
        },
    }]
    asset = AssetIdentityResolver.resolve(evidence)
    assert asset["asset_type"] == "vm"
    assert asset["platform"] == "vm"
    assert asset["os_family"] == "windows"
    assert asset["hostname"] == "pay-win-01"
    assert asset["service"] == "payments"
    assert asset["confidence"] >= 0.75


def test_prometheus_labels_identify_kubernetes_workload():
    evidence = [{
        "type": "metric", "source": "prometheus", "reference": "m1",
        "raw_data": {"name": "cpu_usage", "value": 94.0, "labels": {
            "service": "payment-api", "cluster": "prod-k8s", "namespace": "payment",
            "pod": "payment-api-abc", "node": "worker-03", "environment": "prod",
        }},
    }]
    asset = AssetIdentityResolver.resolve(evidence)
    assert asset["platform"] == "kubernetes"
    assert asset["asset_type"] == "kubernetes_workload"
    assert asset["cluster"] == "prod-k8s"
    assert asset["namespace"] == "payment"
    assert asset["pod"] == "payment-api-abc"


def test_elastic_ecs_identifies_linux_vm():
    evidence = [{
        "type": "log", "source": "elasticsearch", "reference": "l1",
        "raw_data": {
            "host": {"id": "vm-77", "name": "pay-linux-07", "ip": ["10.2.3.4"], "os": {"family": "linux", "name": "Ubuntu", "version": "22.04"}},
            "service": {"name": "payment-worker", "environment": "production"},
            "labels": {"owner": "payment-sre"},
            "message": "cpu high",
        },
    }]
    asset = AssetIdentityResolver.resolve(evidence)
    assert asset["asset_type"] == "vm"
    assert asset["os_family"] == "linux"
    assert asset["hostname"] == "pay-linux-07"
    assert asset["service"] == "payment-worker"
    assert asset["owner"] == "payment-sre"


@pytest.mark.asyncio
async def test_triage_asset_identity_overrides_wrong_model_route(monkeypatch):
    monkeypatch.setattr(settings, "AGENT_ENABLED_AGENTS", ["application", "infrastructure", "kubernetes", "vm", "database"])
    monkeypatch.setattr(settings, "AGENT_MIN_EVIDENCE_ITEMS", 1)
    monkeypatch.setattr(settings, "AGENT_MIN_EVIDENCE_COVERAGE", 0.0)
    payload = {
        "primary_domain": "application",
        "secondary_domains": [],
        "severity": "high",
        "health_status": "degraded",
        "urgency_reason": "cpu high",
        "findings": ["cpu high"],
        "affected_components": ["payment-api"],
        "probable_dependencies": [],
        "blast_radius": "single workload",
        "hypotheses": [],
        "missing_evidence": [],
        "specialist_routes": ["application"],
        "immediate_checks": ["inspect metrics"],
        "confidence": 0.8,
    }
    asset = {"asset_type": "kubernetes_workload", "platform": "kubernetes", "os_family": "linux", "cluster": "prod", "namespace": "payments", "confidence": 1.0}
    evidence = [{"id": "m1", "type": "metric", "source": "prometheus", "raw_data": {"value": 95}}]
    result = await TriageAgent(StaticLLM(payload)).analyze(AgentInput(
        incident_id="i1", service_name="payment-api", evidence_summary="CPU high",
        context={"evidence": evidence, "live_evidence": {"evidence": evidence, "asset_context": asset}},
    ))
    assert result.analysis_details["primary_domain"] == "kubernetes"
    assert result.handoff_agents[:2] == ["kubernetes", "infrastructure"]
    assert result.analysis_details["asset_context"]["cluster"] == "prod"
