import pytest

import apps.orchestrator.e2e_graph as graph_module
from apps.orchestrator.e2e_graph import E2EOrchestrator


class _Memory:
    episodes = []

    def __init__(self, _db):
        pass

    async def add_episode(self, episode):
        self.__class__.episodes.append(episode)
        return "11111111-1111-1111-1111-111111111111"

    async def record_feedback(self, *args, **kwargs):
        return None


def _episode(*, evidence_count: int, verification: str):
    return {
        "evidence_provenance": {"evidence_count": evidence_count},
        "verification": {"status": verification},
        "verification_result": verification,
        "memory_outcome_class": (
            "successful_recovery" if verification == "success" else "failed_attempt"
        ),
    }


@pytest.mark.asyncio
async def test_memory_node_persists_negative_outcome_without_evidence(monkeypatch):
    orchestrator = E2EOrchestrator.__new__(E2EOrchestrator)
    orchestrator.db = object()
    _Memory.episodes = []

    monkeypatch.setattr(
        graph_module.OperationalMemoryBuilder,
        "build",
        lambda _state: _episode(evidence_count=0, verification="failed"),
    )
    monkeypatch.setattr(graph_module, "OperationalMemoryService", _Memory)
    monkeypatch.setattr(
        E2EOrchestrator,
        "_audit",
        staticmethod(lambda *args, **kwargs: None),
    )

    state = {
        "incident_id": "22222222-2222-2222-2222-222222222222",
        "execution_result": {"success": False, "reason": "remote_action_failed"},
        "verification_result": {},
        "findings": [],
        "execution_request": {"action": "start_service"},
    }

    result = await orchestrator._memory_node(state)

    assert len(_Memory.episodes) == 1
    assert result["operational_memory_writeback"]["outcome_class"] == "failed_attempt"


@pytest.mark.asyncio
async def test_memory_node_does_not_promote_evidence_free_success(monkeypatch):
    orchestrator = E2EOrchestrator.__new__(E2EOrchestrator)
    orchestrator.db = object()
    _Memory.episodes = []

    monkeypatch.setattr(
        graph_module.OperationalMemoryBuilder,
        "build",
        lambda _state: _episode(evidence_count=0, verification="success"),
    )
    monkeypatch.setattr(graph_module, "OperationalMemoryService", _Memory)
    monkeypatch.setattr(
        E2EOrchestrator,
        "_audit",
        staticmethod(lambda *args, **kwargs: None),
    )

    state = {
        "incident_id": "22222222-2222-2222-2222-222222222222",
        "execution_result": {"success": True},
        "verification_result": {"status": "success"},
        "findings": [],
    }

    result = await orchestrator._memory_node(state)

    assert _Memory.episodes == []
    assert "operational_memory_writeback" not in result
