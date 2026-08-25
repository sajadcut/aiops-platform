import json

import pytest

from agents.application import ApplicationAgent
from agents.database import DatabaseAgent
from agents.infrastructure import InfrastructureAgent
from agents.kubernetes import KubernetesAgent
from agents.network import NetworkAgent
from agents.security import SecurityAgent
from agents.shared.base import AgentInput
from agents.vm import VMAgent
from integrations.llm.base import LLMAdapter, LLMResponse


class ScenarioLLM(LLMAdapter):
    def __init__(self, payload):
        self.payload = payload

    @property
    def provider_name(self):
        return "scenario"

    async def generate(self, prompt, system_prompt=None, temperature=0.7, max_tokens=1000, **kwargs):
        return LLMResponse(content=json.dumps(self.payload), model="scenario")

    async def generate_with_messages(self, messages, temperature=0.7, max_tokens=1000, **kwargs):
        return await self.generate(messages[-1]["content"], temperature=temperature, max_tokens=max_tokens)


def inp(summary, evidence):
    return AgentInput(incident_id="scenario", service_name="payments", evidence_summary=summary, context={"evidence": evidence})


SCENARIOS = [
    (ApplicationAgent, "5xx spike", [
        {"id":"log-5xx","type":"log","source":"elasticsearch","message":"HTTP 500 increased"},
        {"id":"m-err","type":"metric","source":"prometheus","name":"http_5xx_rate","value":0.2},
    ], {"severity":"high","health_status":"degraded","findings":["5xx error rate increased"],"error_patterns":["HTTP 500"],"affected_components":["payments"],"hypotheses":[{"hypothesis":"application failure","probability":0.8,"evidence_ids":["log-5xx","m-err"],"falsification_checks":["compare dependency errors"]}],"missing_evidence":[],"handoff_agents":["change"],"immediate_checks":["Inspect application logs"],"confidence":0.85}),
    (KubernetesAgent, "CrashLoop/OOM", [
        {"id":"klog","type":"log","source":"kubernetes","message":"container terminated OOMKilled"},
        {"id":"kmem","type":"metric","source":"prometheus","name":"container_memory","value":0.97},
        {"id":"kevent","type":"event","source":"kubernetes","message":"BackOff restarting failed container"},
    ], {"severity":"high","health_status":"degraded","findings":["OOM termination observed"],"workload_signals":["OOMKilled"],"affected_components":["payments-pod"],"hypotheses":[{"hypothesis":"memory pressure","probability":0.9,"evidence_ids":["klog","kmem","kevent"],"falsification_checks":["inspect memory limit and working set"]}],"missing_evidence":[],"handoff_agents":["infrastructure"],"immediate_checks":["Inspect pod events and memory metrics"],"confidence":0.9}),
    (InfrastructureAgent, "CPU saturation", [
        {"id":"cpu","type":"metric","source":"prometheus","name":"cpu_usage","value":0.98},
    ], {"severity":"high","health_status":"degraded","findings":["CPU saturation"],"saturation_signals":["CPU 98%"],"affected_components":["node-1"],"hypotheses":[{"hypothesis":"CPU resource exhaustion","probability":0.8,"evidence_ids":["cpu"],"falsification_checks":["compare load and process demand"]}],"missing_evidence":[],"handoff_agents":["vm"],"immediate_checks":["Inspect CPU metrics"],"confidence":0.8}),
    (VMAgent, "service outage", [
        {"id":"vmetric","type":"metric","source":"vm_telemetry","name":"cpu","value":0.3},
        {"id":"vlog","type":"log","source":"vm_telemetry","message":"service failed"},
    ], {"severity":"high","health_status":"degraded","findings":["service failure in log"],"service_signals":["service failed"],"affected_components":["vm-service"],"hypotheses":[{"hypothesis":"guest service failure","probability":0.8,"evidence_ids":["vlog"],"falsification_checks":["inspect service state"]}],"missing_evidence":[],"handoff_agents":["infrastructure"],"immediate_checks":["Inspect service status"],"remediation_candidates":[],"confidence":0.8}),
    (SecurityAgent, "authentication anomaly", [
        {"id":"authlog","type":"log","source":"elasticsearch","message":"authentication failures increased"},
    ], {"severity":"high","health_status":"degraded","findings":["authentication failures increased"],"authentication_signals":["failed logins"],"suspicious_signals":[],"affected_components":["identity"],"hypotheses":[{"hypothesis":"identity dependency issue","probability":0.65,"evidence_ids":["authlog"],"falsification_checks":["inspect IdP audit trail"]}],"missing_evidence":[],"handoff_agents":["identity"],"immediate_checks":["Inspect authentication audit logs"],"containment_recommendations":[],"confidence":0.75}),
    (DatabaseAgent, "connection exhaustion", [
        {"id":"dbconn","type":"metric","source":"prometheus","name":"db_connections","value":100},
        {"id":"dblog","type":"log","source":"elasticsearch","message":"too many connections"},
    ], {"severity":"high","health_status":"degraded","findings":["connection pool exhausted"],"affected_components":["postgres"],"hypotheses":[{"hypothesis":"database connection exhaustion","probability":0.9,"evidence_ids":["dbconn","dblog"],"falsification_checks":["compare max_connections and active sessions"]}],"missing_evidence":[],"handoff_agents":["application"],"immediate_checks":["Inspect connection metrics"],"confidence":0.9}),
    (NetworkAgent, "latency packet loss", [
        {"id":"net","type":"metric","source":"prometheus","name":"packet_loss","value":0.12},
    ], {"severity":"high","health_status":"degraded","findings":["packet loss observed"],"affected_components":["service path"],"hypotheses":[{"hypothesis":"network path degradation","probability":0.8,"evidence_ids":["net"],"falsification_checks":["compare endpoint and node paths"]}],"missing_evidence":[],"handoff_agents":["infrastructure"],"immediate_checks":["Inspect packet loss and latency metrics"],"confidence":0.8}),
]


@pytest.mark.asyncio
@pytest.mark.parametrize("agent_cls,summary,evidence,payload", SCENARIOS)
async def test_reference_operational_scenarios_are_evidence_grounded(agent_cls, summary, evidence, payload):
    result = await agent_cls(ScenarioLLM(payload)).analyze(inp(summary, evidence))
    assert result.confidence > 0
    assert result.evidence_count == len(evidence)
    assert result.evidence_coverage > 0
    assert result.findings
    for hyp in result.hypotheses:
        assert set(hyp.evidence_ids).issubset(set(result.evidence_ids))
        assert hyp.falsification_checks
