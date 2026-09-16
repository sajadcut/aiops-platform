import json

import pytest

from agents.infrastructure import InfrastructureAgent
from agents.infrastructure.engine import build_infrastructure_analysis
from agents.shared.base import AgentInput
from integrations.llm.base import LLMAdapter, LLMResponse


class StaticInfrastructureLLM(LLMAdapter):
    @property
    def provider_name(self):
        return "static-infrastructure"

    async def generate(self, prompt, system_prompt=None, temperature=0.7, max_tokens=1000, **kwargs):
        payload = {
            "severity": "medium",
            "health_status": "degraded",
            "findings": ["host pressure requires causal validation"],
            "saturation_signals": [],
            "capacity_risks": [],
            "network_signals": [],
            "node_signals": [],
            "probable_dependencies": [],
            "affected_components": ["node-a"],
            "blast_radius": "single host",
            "hypotheses": [{
                "hypothesis": "host CPU scheduling saturation",
                "probability": 0.75,
                "evidence_ids": ["cpu", "load", "runq"],
                "conflicting_evidence_ids": [],
                "falsification_checks": ["Compare run queue and PSI with historical normal"],
                "impacted_components": ["node-a"],
                "recommended_next_evidence": ["per-process CPU attribution"],
            }],
            "missing_evidence": [],
            "handoff_agents": [],
            "immediate_checks": ["Inspect process CPU attribution"],
            "escalation_target": "infrastructure-sre",
            "risk_level": "medium",
            "uncertainty_reason": "",
            "confidence": 0.8,
        }
        return LLMResponse(content=json.dumps(payload), model="static-infrastructure")

    async def generate_with_messages(self, messages, temperature=0.7, max_tokens=1000, **kwargs):
        return await self.generate(messages[-1]["content"], temperature=temperature, max_tokens=max_tokens)


def metric(evidence_id, name, value, timestamp="2026-09-16T10:05:00Z", **raw):
    return {
        "id": evidence_id,
        "type": "metric",
        "source": "prometheus",
        "name": name,
        "value": value,
        "timestamp": timestamp,
        "raw_data": raw,
    }


def analyze(evidence):
    return build_infrastructure_analysis(
        evidence,
        service_name="checkout-node",
        context={"summary": {"incident_start": "2026-09-16T10:00:00Z"}},
    )


def test_cpu_saturation_requires_scheduling_pressure_not_utilization_alone():
    result = analyze([
        metric("cpu", "node_cpu_utilization_percent", 96),
        metric("cores", "node_cpu_cores", 4),
        metric("load", "node_load1", 7.2),
        metric("runq", "node_run_queue", 5),
        metric("psi", "node_psi_cpu_percent", 18),
    ])

    cpu = result["health_matrix"]["cpu"]
    assert cpu["status"] == "saturated"
    assert cpu["observations"]["load_per_core"] == 1.8
    assert cpu["anomaly_start"] == "2026-09-16T10:05:00+00:00"
    assert cpu["incident_correlation_seconds"] == 300.0
    assert any(row["pattern"] == "cpu_saturation" for row in result["causal_patterns"])


def test_memory_pressure_uses_available_memory_page_faults_and_psi():
    result = analyze([
        metric("avail", "node_memory_available_percent", 7),
        metric("total", "node_memory_total_percent", 100),
        metric("faults", "node_major_page_faults", 40),
        metric("reclaim", "node_direct_reclaim_rate", 25),
        metric("psi", "node_psi_memory_percent", 17),
    ])

    memory = result["health_matrix"]["memory"]
    assert memory["status"] == "pressured"
    assert memory["observations"]["psi_memory"] == 17
    assert "faults" in memory["evidence_ids"]


def test_swap_storm_is_distinct_from_generic_high_memory_usage():
    result = analyze([
        metric("avail", "node_memory_available_percent", 8),
        metric("total", "node_memory_total_percent", 100),
        metric("swap-in", "node_swap_in_pages_per_second", 220),
        metric("swap-out", "node_swap_out_pages_per_second", 180),
        metric("faults", "node_major_page_faults", 30),
    ])

    memory = result["health_matrix"]["memory"]
    assert memory["status"] == "swap_storm"
    assert memory["observations"]["swap_in"] == 220
    assert memory["observations"]["swap_out"] == 180


def test_oom_event_has_stronger_semantics_than_memory_percentage():
    result = analyze([
        metric("avail", "node_memory_available_percent", 15),
        {
            "id": "oom-log",
            "type": "log",
            "source": "zabbix",
            "timestamp": "2026-09-16T10:03:00Z",
            "message": "kernel: OOM killed process 4412 java due to out of memory",
        },
    ])

    memory = result["health_matrix"]["memory"]
    assert memory["status"] == "oom_pressure"
    assert "oom-log" in memory["evidence_ids"]
    assert result["event_signals"]["oom"]


def test_disk_io_bottleneck_and_cpu_iowait_create_storage_handoff():
    result = analyze([
        metric("iowait", "node_cpu_iowait_percent", 34),
        metric("disk-util", "node_disk_utilization_percent", 96),
        metric("await", "node_disk_await_ms", 48),
        metric("queue", "node_disk_queue_depth", 6),
        metric("psi", "node_psi_io_percent", 21),
    ])

    assert result["health_matrix"]["cpu"]["status"] == "waiting_on_io"
    assert result["health_matrix"]["disk"]["status"] == "io_bottleneck"
    pattern = next(row for row in result["causal_patterns"] if row["pattern"] == "storage_bottleneck_expressed_as_cpu_iowait")
    assert pattern["handoff"] == "storage"
    assert "storage" in result["handoff_candidates"]


def test_inode_exhaustion_is_not_hidden_by_filesystem_byte_capacity():
    result = analyze([
        metric("fs", "node_filesystem_usage_percent", 58),
        metric("inode", "node_inode_usage_percent", 97),
    ])

    disk = result["health_matrix"]["disk"]
    assert disk["status"] == "inode_pressure"
    assert disk["observations"]["filesystem_usage"] == 58
    assert disk["observations"]["inode_usage"] == 97


def test_healthy_high_cpu_utilization_is_not_mislabeled_as_saturation():
    result = analyze([
        metric("cpu", "node_cpu_utilization_percent", 92),
        metric("cores", "node_cpu_cores", 8),
        metric("load", "node_load1", 3.2),
        metric("runq", "node_run_queue", 1),
        metric("psi", "node_psi_cpu_percent", 1.5),
        metric("throttle", "node_cpu_throttling_percent", 0),
        metric("iowait", "node_cpu_iowait_percent", 1),
        metric("steal", "node_cpu_steal_percent", 0.5),
    ])

    cpu = result["health_matrix"]["cpu"]
    assert cpu["status"] == "high_utilization_healthy"
    assert any(row["pattern"] == "high_utilization_but_healthy" for row in result["causal_patterns"])
    assert not any(row["pattern"] == "cpu_saturation" for row in result["causal_patterns"])


def test_capacity_analysis_tracks_multiday_percentiles_growth_and_sudden_delta():
    result = analyze([
        metric(
            "mem",
            "node_memory_working_set_bytes",
            900,
            baseline=400,
            historical_p95=600,
            historical_p99=700,
            baseline_days=7,
            growth_rate=18,
        ),
    ])

    capacity = result["capacity_analysis"]
    assert capacity["multi_day_baseline_available"] is True
    assert capacity["growth_trend_candidates"]
    assert capacity["above_historical_p99"]
    assert result["health_matrix"]["capacity"]["status"] == "trend_risk"
    assert any(row["pattern"] == "resource_leak_candidate" for row in result["causal_patterns"])


@pytest.mark.asyncio
async def test_infrastructure_agent_exposes_health_matrix_and_remains_analysis_only():
    evidence = [
        metric("cpu", "node_cpu_utilization_percent", 96),
        metric("cores", "node_cpu_cores", 4),
        metric("load", "node_load1", 7),
        metric("runq", "node_run_queue", 5),
        metric("psi", "node_psi_cpu_percent", 15),
    ]
    incident = AgentInput(
        incident_id="infra-use-1",
        service_name="checkout-node",
        evidence_summary="CPU scheduling pressure",
        context={
            "evidence": evidence,
            "summary": {"incident_start": "2026-09-16T10:00:00Z"},
        },
    )

    result = await InfrastructureAgent(StaticInfrastructureLLM()).analyze(incident)

    assert result.analysis_details["infrastructure_health_matrix"]["cpu"]["status"] == "saturated"
    assert result.analysis_details["infrastructure_health_matrix"]["cpu"]["incident_correlation_seconds"] == 300.0
    assert result.analysis_details["execution_boundary"] == "analysis_only"
    assert result.hypotheses[0].evidence_ids == ["cpu", "load", "runq"]
    assert all(action.read_only for action in result.recommended_actions)
