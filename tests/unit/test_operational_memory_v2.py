import pytest

from apps.memory_service import OperationalMemoryService
from apps.memory_service.builder import OperationalMemoryBuilder
from knowledge import EmbeddingService


def _state():
    return {
        "incident_id": "a1415045-537d-437c-a379-f0d6e8e05d8a",
        "service_name": "nginx",
        "evidence_summary": "nginx inactive and port 86 unavailable",
        "context": {
            "incident": {
                "source": "zabbix",
                "summary": "NeoBanking-Checkport 86 is down",
                "severity": "Average",
            },
            "trigger_signal": {
                "source": "zabbix",
                "signal_type": "problem",
                "summary": "NeoBanking-Checkport 86 is down",
            },
            "evidence": [
                {
                    "source": "vm_mcp",
                    "type": "metric",
                    "reference": "vm:service_status:1",
                    "raw_data": {
                        "diagnostic": "service_status",
                        "service": "nginx",
                        "target": "10.100.6.199",
                    },
                }
            ],
        },
        "findings": [
            {
                "agent_name": "vm",
                "statement": "nginx is inactive; historical reason is not proven",
                "confidence": 0.9,
                "evidence_ids": ["vm:service_status:1"],
                "missing_evidence": ["audit logs identifying who stopped nginx"],
            }
        ],
        "coordination": {
            "missing_evidence": ["historical systemd journal"],
            "contradictions": [],
        },
        "execution_request": {
            "tool_name": "ssh_vm",
            "action": "start_service",
            "target": "10.100.6.199",
            "parameters": {
                "service": "nginx",
                "target_port": 86,
                "password": "must-not-survive",
            },
            "runbook_id": "vm-service-recovery",
            "runbook_version": "1.1",
        },
        "execution_result": {
            "success": True,
            "tool_name": "ssh_vm",
            "action": "start_service",
            "target": "10.100.6.199",
            "execution_time": 0.4,
        },
        "verification_result": {
            "status": "success",
            "confidence": 0.92,
            "before_state": {
                "service_active": 0,
                "port_listening": 0,
                "tcp_reachable": 0,
                "memory_usage": 8,
            },
            "after_state": {
                "service_active": 1,
                "port_listening": 1,
                "tcp_reachable": 1,
                "memory_usage": 10,
            },
            "metric_directions": {
                "service_active": "higher_is_better",
                "port_listening": "higher_is_better",
                "tcp_reachable": "higher_is_better",
                "memory_usage": "lower_is_better",
            },
            "evidence_refs": ["vm:service_status:1"],
            "message": "recovered",
        },
    }


def test_builder_preserves_uncertain_root_cause_and_actual_execution():
    episode = OperationalMemoryBuilder.build(_state())
    assert episode["root_cause_status"] == "unconfirmed"
    assert episode["actual_remediation"]["action"] == "start_service"
    assert episode["actual_remediation"]["tool_name"] == "ssh_vm"
    assert episode["actual_remediation"]["parameters"]["password"] == "[REDACTED]"
    assert set(episode["verification"]["recovered_signals"]) == {
        "service_active",
        "port_listening",
        "tcp_reachable",
    }
    assert "memory_usage_increase" in episode["verification"]["expected_side_effects"]
    assert episode["memory_outcome_class"] == "successful_recovery"
    assert "Historical root cause status is unconfirmed" in episode["reusable_lesson"]
    assert "must-not-survive" not in episode["embedding_document"]
    assert "must-not-survive" not in episode["search_document"]


def test_builder_redacts_compound_secret_keys_before_storage_and_embedding():
    state = _state()
    state["execution_request"]["parameters"].update(
        {
            "db_password": "db-secret-value",
            "service_token": "service-token-value",
            "client_secret": "client-secret-value",
            "nested": {
                "redis_password": "redis-secret-value",
                "safe_label": "payments",
            },
        }
    )
    episode = OperationalMemoryBuilder.build(state)
    parameters = episode["actual_remediation"]["parameters"]

    assert parameters["db_password"] == "[REDACTED]"
    assert parameters["service_token"] == "[REDACTED]"
    assert parameters["client_secret"] == "[REDACTED]"
    assert parameters["nested"]["redis_password"] == "[REDACTED]"
    assert parameters["nested"]["safe_label"] == "payments"

    serialized = str(episode)
    for secret in (
        "db-secret-value",
        "service-token-value",
        "client-secret-value",
        "redis-secret-value",
    ):
        assert secret not in serialized


def test_episode_fingerprint_is_stable_and_changes_with_real_execution():
    first = OperationalMemoryBuilder.build(_state())
    second = OperationalMemoryBuilder.build(_state())
    assert first["episode_fingerprint"] == second["episode_fingerprint"]
    assert len(first["episode_fingerprint"]) == 64

    changed_state = _state()
    changed_state["execution_request"]["action"] = "restart_service"
    changed_state["execution_result"]["action"] = "restart_service"
    changed = OperationalMemoryBuilder.build(changed_state)
    assert changed["episode_fingerprint"] != first["episode_fingerprint"]


def test_episode_fingerprint_is_stable_across_evidence_reference_refresh():
    first_state = _state()
    second_state = _state()
    second_state["context"]["evidence"][0]["reference"] = "vm:service_status:refresh-2"
    second_state["findings"][0]["evidence_ids"] = ["vm:service_status:refresh-2"]
    second_state["verification_result"]["evidence_refs"] = ["vm:service_status:refresh-2"]

    first = OperationalMemoryBuilder.build(first_state)
    second = OperationalMemoryBuilder.build(second_state)
    assert first["episode_fingerprint"] == second["episode_fingerprint"]


def test_episode_fingerprint_is_not_changed_by_secret_value_rotation():
    first_state = _state()
    second_state = _state()
    first_state["execution_request"]["parameters"]["password"] = "first-secret"
    second_state["execution_request"]["parameters"]["password"] = "second-secret"
    first = OperationalMemoryBuilder.build(first_state)
    second = OperationalMemoryBuilder.build(second_state)
    assert first["episode_fingerprint"] == second["episode_fingerprint"]


def test_builder_preserves_investigation_rca_and_evidence_requests():
    state = _state()
    state["triage_result"] = {
        "summary": "Live evidence shows nginx inactive and port 86 unavailable.",
        "confidence": 0.91,
    }
    state["final_plan"] = (
        "RCA synthesis: current service state is proven unhealthy; "
        "historical stop cause remains unconfirmed."
    )
    state["findings"][0]["recommended_checks"] = [
        "inspect historical systemd journal"
    ]
    state["findings"][0]["evidence_requests"] = [
        {
            "evidence_type": "service_logs",
            "reason": "identify the last transition before nginx became inactive",
            "preferred_source": "vm_mcp",
        }
    ]

    episode = OperationalMemoryBuilder.build(state)
    investigation = episode["investigation"]

    assert investigation["triage"]["summary"].startswith("Live evidence")
    assert investigation["rca_synthesis"].startswith("RCA synthesis")
    assert investigation["specialist_findings"][0]["agent"] == "vm"
    assert investigation["specialist_findings"][0]["recommended_checks"] == [
        "inspect historical systemd journal"
    ]
    assert investigation["evidence_requests"][0]["evidence_type"] == "service_logs"
    assert "Live evidence shows nginx inactive" in investigation["investigation_summary"]
    assert "RCA synthesis" in episode["embedding_document"]
    assert "historical stop cause remains unconfirmed" in episode["search_document"]


def test_builder_normalizes_failed_execution_without_verification_for_learning():
    state = _state()
    state["execution_result"] = {
        "success": False,
        "tool_name": "ssh_vm",
        "action": "start_service",
        "target": "10.100.6.199",
        "reason": "mcp_write_failed",
    }
    state["verification_result"] = {}

    episode = OperationalMemoryBuilder.build(state)

    assert episode["memory_outcome_class"] == "failed_recovery"
    assert episode["verification_result"] == "failed"
    assert episode["verification"]["status"] == "failed"
    assert episode["actual_remediation"]["execution_success"] is False
    assert episode["outcome"] == "mcp_write_failed"


def test_builder_preserves_historical_memory_lineage_without_promoting_it_to_evidence():
    state = _state()
    state["findings"][0]["historical_memory_ids"] = [
        "11111111-1111-1111-1111-111111111111",
        "11111111-1111-1111-1111-111111111111",
        "22222222-2222-2222-2222-222222222222",
    ]

    episode = OperationalMemoryBuilder.build(state)

    assert episode["investigation"]["historical_memory_ids"] == [
        "11111111-1111-1111-1111-111111111111",
        "22222222-2222-2222-2222-222222222222",
    ]
    evidence_refs = episode["evidence_provenance"]["evidence_refs"]
    assert "11111111-1111-1111-1111-111111111111" not in evidence_refs
    assert "22222222-2222-2222-2222-222222222222" not in evidence_refs


def test_builder_does_not_convert_recovery_into_confirmed_cause():
    state = _state()
    state["triage_result"] = {
        "summary": "service was stopped",
        "confidence": 0.99,
    }
    episode = OperationalMemoryBuilder.build(state)
    assert episode["root_cause_status"] == "unconfirmed"


class _FakeScalars:
    def __init__(self, items):
        self.items = items

    def first(self):
        return self.items[0] if self.items else None


class _FakeExecuteResult:
    def __init__(self, items=None):
        self.items = list(items or [])

    def scalars(self):
        return _FakeScalars(self.items)


class _FakeDB:
    def __init__(self):
        self.items = []
        self.commits = 0
        self.rollbacks = 0

    def add(self, item):
        self.items.append(item)

    async def execute(self, _statement):
        return _FakeExecuteResult()

    async def commit(self):
        self.commits += 1

    async def rollback(self):
        self.rollbacks += 1

    async def refresh(self, item):
        return None

    async def get(self, _model, entry_id):
        for item in self.items:
            if item.id == entry_id:
                return item
        return None


@pytest.mark.asyncio
async def test_embedding_failure_keeps_core_episode(monkeypatch):
    async def fail_embedding(_text):
        raise RuntimeError("embedding-down")

    monkeypatch.setattr(
        EmbeddingService,
        "generate_embedding",
        fail_embedding,
    )
    db = _FakeDB()
    service = OperationalMemoryService(db)
    episode = OperationalMemoryBuilder.build(_state())

    memory_id = await service.add_episode(episode)

    assert memory_id is not None
    assert len(db.items) == 1
    assert db.items[0].embedding is None
    assert db.items[0].embedding_status == "failed"
    assert db.commits >= 2


def test_builder_redacts_secrets_from_persisted_and_embedding_fields():
    state = _state()
    state["context"]["incident"]["summary"] = "nginx failed token=super-secret-value"
    state["execution_request"]["parameters"]["authorization"] = "Bearer abc.def.ghi"
    state["execution_request"]["parameters"]["password"] = "hunter2"
    episode = OperationalMemoryBuilder.build(state)
    serialized = str(episode).lower()
    embedding = episode["embedding_document"].lower()
    assert "super-secret-value" not in serialized
    assert "abc.def.ghi" not in serialized
    assert "hunter2" not in serialized
    assert "super-secret-value" not in embedding
    assert "abc.def.ghi" not in embedding
    assert "hunter2" not in embedding

def test_feedback_reuse_event_name_is_stable_and_low_cardinality():
    from pathlib import Path

    source = Path("apps/memory_service/feedback.py").read_text(encoding="utf-8")
    assert '"aiops.memory.reused"' in source
    for attribute in (
        "memory_id",
        "target_incident_id",
        "service_name",
        "environment",
        "retrieval_mode",
        "rank_position",
        "verification_status",
        "helpful",
        "reward_score",
    ):
        assert f"{attribute}=" in source

def test_builder_retains_actual_execution_timestamps():
    state = _state()
    state["execution_result"]["execution_started_at"] = "2026-09-23T10:00:00+00:00"
    state["execution_result"]["execution_completed_at"] = "2026-09-23T10:00:00.400000+00:00"

    episode = OperationalMemoryBuilder.build(state)
    remediation = episode["actual_remediation"]

    assert remediation["execution_started_at"] == "2026-09-23T10:00:00+00:00"
    assert remediation["execution_completed_at"] == "2026-09-23T10:00:00.400000+00:00"
    assert remediation["execution_duration"] == 0.4


@pytest.mark.asyncio
async def test_execution_service_results_include_timestamps():
    from apps.execution_service import ExecutionRequest, ExecutionService

    result = await ExecutionService.execute(
        ExecutionRequest(
            tool_name="missing-memory-test-tool",
            action="noop",
            target="test-target",
        )
    )

    assert result.execution_started_at.tzinfo is not None
    assert result.execution_completed_at.tzinfo is not None
    assert result.execution_completed_at >= result.execution_started_at


def test_rrf_metadata_compatibility_penalizes_version_and_config_mismatch():
    from apps.memory_service.retrieval import rrf_score
    from domain.models import MemoryEntry

    base = {
        "pattern": "nginx inactive port unavailable",
        "service_scope": "nginx",
        "environment": "test",
        "asset_type": "vm",
        "trigger": {"signal_type": "problem"},
        "service_version": "1.24.0",
        "configuration_fingerprint": "cfg-current",
        "verification_result": "success",
        "effectiveness_score": 0.5,
        "memory_outcome_class": "successful_recovery",
    }
    matching = MemoryEntry(**base)
    mismatched = MemoryEntry(
        **{
            **base,
            "service_version": "2.0.0",
            "configuration_fingerprint": "cfg-old",
        }
    )
    common = {
        "service_scope": "nginx",
        "environment": "test",
        "mode": "SIMILAR_INCIDENT",
        "query": "nginx inactive port unavailable",
        "asset_type": "vm",
        "signal_type": "problem",
        "service_version": "1.24.0",
        "configuration_fingerprint": "cfg-current",
    }

    matching_score = rrf_score(
        {"entry": matching, "vector_rank": 1, "vector_similarity": 0.9},
        **common,
    )
    mismatched_score = rrf_score(
        {"entry": mismatched, "vector_rank": 1, "vector_similarity": 0.9},
        **common,
    )

    assert matching_score > mismatched_score

