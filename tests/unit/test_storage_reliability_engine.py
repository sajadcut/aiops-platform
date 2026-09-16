import json

import pytest

from agents.shared.base import AgentInput
from agents.storage import StorageAgent
from agents.storage.engine import build_storage_reliability_analysis
from integrations.llm.base import LLMAdapter, LLMResponse


def metric(eid, name, value, *, timestamp=None, host="node-a", device="sda", mount="/var", **raw):
    item = {
        "id": eid,
        "type": "metric",
        "source": "prometheus",
        "name": name,
        "value": value,
        "raw_data": {"host": host, "device": device, "mount": mount, **raw},
    }
    if timestamp:
        item["timestamp"] = timestamp
    return item


def telemetry(eid, diagnostic, *, timestamp=None, source="vm_telemetry", host="node-a", device="sda", mount="/var", **raw):
    item = {
        "id": eid,
        "type": "telemetry",
        "source": source,
        "raw_data": {"diagnostic": diagnostic, "host": host, "device": device, "mount": mount, **raw},
    }
    if timestamp:
        item["timestamp"] = timestamp
    return item


def analyze(evidence, **context):
    return build_storage_reliability_analysis(
        evidence,
        service_name="payments",
        context={"time_range": {"start": "2026-09-16T10:00:00Z", "end": "2026-09-16T10:10:00Z"}, **context},
    )


def codes(result):
    return {row["code"] for row in result["cause_candidates"]}


def candidate(result, code):
    return next(row for row in result["cause_candidates"] if row["code"] == code)


def test_capacity_exhaustion_is_distinct_from_inode_exhaustion():
    result = analyze([
        metric("capacity", "node_filesystem_used_percent", 97.5),
        metric("inode", "node_filesystem_inode_usage_percent", 62.0),
    ])
    assert "disk_full" in codes(result)
    assert "inode_full" not in codes(result)
    assert result["capacity_analysis"]["capacity_utilization"] == 0.975
    assert candidate(result, "disk_full")["root_cause_status"] == "candidate_requires_falsification"


def test_inode_exhaustion_is_independent_of_capacity():
    result = analyze([
        metric("capacity", "node_filesystem_used_percent", 71.0),
        metric("inode", "node_filesystem_inode_usage_percent", 99.2),
    ])
    assert "inode_full" in codes(result)
    assert "disk_full" not in codes(result)
    assert candidate(result, "inode_full")["confidence"] >= 0.9


def test_high_await_queue_and_utilization_create_io_saturation_candidate():
    result = analyze([
        metric("await", "disk_io_latency_ms", 48),
        metric("queue", "disk_queue_depth", 7.5),
        metric("util", "disk_utilization", 96),
        metric("iops", "disk_iops", 4200),
    ])
    assert "io_saturation" in codes(result)
    row = candidate(result, "io_saturation")
    assert set(row["evidence_ids"]) >= {"await", "queue", "util"}
    assert row["causal_role"] == "storage_origin_candidate"


def test_device_io_error_is_stronger_than_smart_warning_alone():
    result = analyze([
        metric("error", "disk_errors_total", 3),
        telemetry("smart", "smart", smart_status="warning", current_pending_sector=2),
    ])
    row = candidate(result, "failing_physical_device")
    assert row["confidence"] >= 0.8
    assert "error" in row["evidence_ids"]
    assert "SMART warnings" in result["smart_policy"]


def test_smart_warning_alone_is_probabilistic_not_certain_failure():
    result = analyze([
        telemetry("smart", "smart", smart_status="warning", current_pending_sector=1, reallocated_sector_count=4),
    ])
    row = candidate(result, "failing_physical_device")
    assert row["confidence"] < 0.7
    assert "do not prove" in row["basis"]
    assert result["device_health_analysis"]["smart"][0]["interpretation_policy"].startswith("SMART warning is risk evidence")


def test_slow_distributed_storage_surfaces_ceph_health_and_remote_latency():
    result = analyze([
        telemetry(
            "ceph",
            "ceph_health",
            source="ceph",
            osd_state="down",
            pg_state="active+degraded",
            slow_ops=12,
            recovery_state="backfilling",
            replica_health="degraded",
        ),
        metric("latency", "storage_latency_ms", 65, device="rbd0"),
        metric("queue", "io_queue_depth", 4, device="rbd0"),
    ])
    assert "distributed_storage_degraded" in codes(result)
    assert "networked_storage_latency" in codes(result)
    ceph = result["distributed_storage_analysis"]["ceph"][0]
    assert ceph["osd_state"] == "down"
    assert ceph["slow_ops"] == 12


def test_healthy_busy_disk_is_not_labeled_io_saturation():
    result = analyze([
        metric("util", "disk_utilization", 88),
        metric("iops", "disk_iops", 8500),
        metric("throughput", "disk_throughput_bytes_per_second", 800_000_000),
        metric("await", "disk_io_latency_ms", 4.5),
        metric("queue", "disk_queue_depth", 0.6),
        metric("errors", "disk_errors_total", 0),
    ])
    assert "healthy_busy_storage" in codes(result)
    assert "io_saturation" not in codes(result)
    assert result["causal_attribution"] == "storage_busy_but_not_currently_faulted"


def test_database_driven_io_pressure_is_workload_candidate_and_temporally_correlated():
    result = analyze([
        metric("db", "database_write_rate", 9200, timestamp="2026-09-16T10:00:00Z", domain="database"),
        metric("await", "disk_io_latency_ms", 52, timestamp="2026-09-16T10:02:00Z"),
        metric("queue", "disk_queue_depth", 6, timestamp="2026-09-16T10:02:05Z"),
        metric("util", "disk_utilization", 97, timestamp="2026-09-16T10:02:05Z"),
    ])
    assert "database_driven_storage_pressure" in codes(result)
    row = candidate(result, "database_driven_storage_pressure")
    assert row["causal_role"] == "workload_driven_pressure_candidate"
    correlation = next(row for row in result["temporal_correlation"]["correlations"] if row["domain"] == "database")
    assert correlation["ordering"] == "domain_precedes"
    assert result["causal_attribution"] == "storage_is_plausible_cause_candidate"


def test_application_write_burst_is_separate_from_storage_origin():
    result = analyze([
        metric("app", "application_write_rate", 12000, timestamp="2026-09-16T10:00:00Z", domain="application"),
        metric("await", "disk_io_latency_ms", 35, timestamp="2026-09-16T10:01:00Z"),
        metric("queue", "disk_queue_depth", 5, timestamp="2026-09-16T10:01:00Z"),
        metric("util", "disk_utilization", 95, timestamp="2026-09-16T10:01:00Z"),
    ])
    assert "application_write_burst" in codes(result)
    assert candidate(result, "application_write_burst")["handoff"] == "application"


def test_persistent_volume_attach_mount_and_multipath_failure_are_structured():
    result = analyze([
        telemetry("path", "multipath", device="dm-0", path_state="degraded", active_paths=1, failed_paths=1),
        telemetry("pvc", "persistent_volume", source="kubernetes", volume="data-pvc", pvc_state="Pending", attach_error="attach timeout"),
    ])
    assert "persistent_volume_path_issue" in codes(result)
    assert result["path_analysis"]["multipath"][0]["failed_paths"] == 1
    assert result["path_analysis"]["persistent_volumes"][0]["state"] == "pending"


def test_read_only_filesystem_is_corruption_symptom_not_automatic_physical_failure():
    result = analyze([
        {"id": "fs", "type": "log", "source": "kernel", "message": "EXT4-fs error followed by read-only file system", "raw_data": {"host": "node-a", "device": "sda", "mount": "/var"}},
    ])
    assert "filesystem_corruption_symptom" in codes(result)
    assert "failing_physical_device" not in codes(result)


class CapturingStorageLLM(LLMAdapter):
    def __init__(self):
        self.prompt = ""

    @property
    def provider_name(self):
        return "storage-capturing-test"

    async def generate(self, prompt, system_prompt=None, temperature=0.7, max_tokens=1000, **kwargs):
        self.prompt = prompt
        payload = {
            "severity": "high",
            "health_status": "degraded",
            "findings": ["storage latency is elevated under database write pressure"],
            "affected_components": ["node-a", "/var"],
            "probable_dependencies": ["database"],
            "blast_radius": "payments write path",
            "hypotheses": [{
                "hypothesis": "database write pressure is saturating the storage queue",
                "probability": 0.78,
                "evidence_ids": ["db", "await", "queue"],
                "conflicting_evidence_ids": [],
                "falsification_checks": ["compare queue latency after database write rate returns to baseline"],
                "impacted_components": ["node-a", "/var"],
                "recommended_next_evidence": ["historical DB write rate and storage await"],
            }],
            "missing_evidence": [],
            "handoff_agents": ["database"],
            "immediate_checks": ["Inspect storage await, queue and database write rate"],
            "confidence": 0.78,
        }
        return LLMResponse(content=json.dumps(payload), model="scenario")

    async def generate_with_messages(self, messages, temperature=0.7, max_tokens=1000, **kwargs):
        return await self.generate(messages[-1]["content"], temperature=temperature, max_tokens=max_tokens)


@pytest.mark.asyncio
async def test_storage_agent_exposes_deterministic_layers_before_llm_synthesis():
    adapter = CapturingStorageLLM()
    incident = AgentInput(
        incident_id="inc-storage",
        service_name="payments",
        evidence_summary="write latency increased",
        context={"evidence": [
            metric("db", "database_write_rate", 9000, domain="database"),
            metric("await", "disk_io_latency_ms", 45),
            metric("queue", "disk_queue_depth", 5),
            metric("util", "disk_utilization", 96),
        ]},
    )
    result = await StorageAgent(adapter).analyze(incident)
    assert "STORAGE_ANALYSIS=" in adapter.prompt
    assert result.analysis_details["io_analysis"]["latency_await_ms"] == 45
    assert "database_driven_storage_pressure" in {row["code"] for row in result.analysis_details["cause_candidates"]}
    assert result.analysis_details["execution_boundary"] == "analysis_only"
    assert all(action.read_only for action in result.recommended_actions)
