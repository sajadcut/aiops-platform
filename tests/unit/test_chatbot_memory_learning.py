from types import SimpleNamespace

import pytest

import apps.chatbot.service as chatbot_module
from apps.chatbot.service import ChatbotService


class FakeDB:
    def __init__(self):
        self.commits = 0

    async def commit(self):
        self.commits += 1


class FakeIncidentRepository:
    statuses = []

    def __init__(self, db):
        self.db = db

    async def set_status(self, incident_id, status):
        self.__class__.statuses.append((incident_id, status))


class FakeMemoryService:
    episodes = []

    def __init__(self, db):
        self.db = db

    async def add_episode(self, episode):
        self.__class__.episodes.append(episode)
        return "memory-1"


@pytest.mark.asyncio
async def test_chatbot_verified_execution_writes_resolved_memory(monkeypatch):
    FakeIncidentRepository.statuses = []
    FakeMemoryService.episodes = []
    monkeypatch.setattr(
        chatbot_module,
        "IncidentRepository",
        FakeIncidentRepository,
    )
    monkeypatch.setattr(
        chatbot_module,
        "OperationalMemoryService",
        FakeMemoryService,
    )

    execution = SimpleNamespace(
        success=True,
        error=None,
        reason=None,
        model_dump=lambda: {
            "success": True,
            "tool_name": "ssh_vm",
            "action": "start_service",
            "target": "10.100.6.199",
        },
    )
    proposal = {
        "incident_id": "a1415045-537d-437c-a379-f0d6e8e05d8a",
        "tool_name": "ssh_vm",
        "action": "start_service",
        "target": "10.100.6.199",
        "parameters": {"service": "nginx", "target_port": 86},
        "risk_level": "high",
    }

    await ChatbotService()._record_memory_after_mutation(
        FakeDB(),
        proposal=proposal,
        proposal_id="proposal-1",
        execution=execution,
        verification={
            "verified": True,
            "source": "vm_mcp",
            "result": {"active": True},
        },
        approval_id="approval-1",
    )

    assert FakeIncidentRepository.statuses[-1][1] == "resolved"
    episode = FakeMemoryService.episodes[-1]
    assert episode["actual_remediation"]["action"] == "start_service"
    assert episode["verification_result"] == "success"
    assert episode["memory_outcome_class"] == "successful_recovery"


@pytest.mark.asyncio
async def test_chatbot_unverified_execution_escalates(monkeypatch):
    FakeIncidentRepository.statuses = []
    FakeMemoryService.episodes = []
    monkeypatch.setattr(
        chatbot_module,
        "IncidentRepository",
        FakeIncidentRepository,
    )
    monkeypatch.setattr(
        chatbot_module,
        "OperationalMemoryService",
        FakeMemoryService,
    )

    execution = SimpleNamespace(
        success=True,
        error=None,
        reason=None,
        model_dump=lambda: {
            "success": True,
            "tool_name": "ssh_vm",
            "action": "start_service",
            "target": "10.100.6.199",
        },
    )
    proposal = {
        "incident_id": "a1415045-537d-437c-a379-f0d6e8e05d8a",
        "tool_name": "ssh_vm",
        "action": "start_service",
        "target": "10.100.6.199",
        "parameters": {"service": "nginx"},
        "risk_level": "high",
    }

    await ChatbotService()._record_memory_after_mutation(
        FakeDB(),
        proposal=proposal,
        proposal_id="proposal-2",
        execution=execution,
        verification={
            "verified": False,
            "source": "vm_mcp",
            "error": "verification_unavailable",
        },
        approval_id="approval-2",
    )

    assert FakeIncidentRepository.statuses[-1][1] == "escalated"
    assert FakeMemoryService.episodes[-1]["verification_result"] == "inconclusive"
