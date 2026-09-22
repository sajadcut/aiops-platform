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
