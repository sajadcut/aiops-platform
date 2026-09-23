from types import SimpleNamespace
from uuid import uuid4

import pytest

import apps.chatbot.service as chatbot_service_module
from apps.chatbot.service import ChatbotService
from apps.chatbot.tools import ToolIntent
from apps.security.rbac import allowed
from domain.contracts.config import settings


class FakeKnowledgeRAGService:
    calls = []

    async def search(self, query, limit=5, **kwargs):
        type(self).calls.append(("search", query, limit, kwargs))
        return [{"source": "cognia", "content": "approved runbook"}]

    async def register_knowledge(self, **kwargs):
        type(self).calls.append(("register", kwargs))
        return {"knowledgeId": 9001, "revisionId": 12001, "status": "Processing"}

    async def get_knowledge_detail(self, **kwargs):
        type(self).calls.append(("detail", kwargs))
        return {"knowledgeId": kwargs["knowledge_id"], "currentCandidateRevisionId": 12001}

    async def create_revision(self, **kwargs):
        type(self).calls.append(("revision", kwargs))
        return {"knowledgeId": kwargs["knowledge_id"], "revisionId": 12002, "revisionNumber": 2}

    async def get_processing_status(self, **kwargs):
        type(self).calls.append(("processing", kwargs))
        return {"state": "Processing"}


@pytest.fixture(autouse=True)
def reset_calls():
    FakeKnowledgeRAGService.calls = []


def test_chatbot_cognia_rbac_separates_read_and_write():
    assert allowed("viewer", "read:knowledge") is True
    assert allowed("viewer", "write:knowledge") is False
    assert allowed("operator", "write:knowledge") is True
    assert allowed("sre", "write:knowledge") is True


@pytest.mark.asyncio
async def test_chatbot_cognia_read_uses_governed_rag(monkeypatch):
    monkeypatch.setattr(chatbot_service_module, "KnowledgeRAGService", FakeKnowledgeRAGService)
    intent = ToolIntent(
        "cognia_search",
        "cognia_knowledge_read",
        "search",
        "cognia",
        {"query": "nginx restart runbook", "limit": 3},
        False,
        "low",
    )

    result = await ChatbotService()._execute_read(intent, "session-1")

    assert result["source"] == "cognia"
    assert result["result"][0]["content"] == "approved runbook"
    assert FakeKnowledgeRAGService.calls[0][:3] == ("search", "nginx restart runbook", 3)


@pytest.mark.asyncio
async def test_chatbot_cognia_register_uses_allowlisted_default_scope_and_idempotency(monkeypatch):
    monkeypatch.setattr(chatbot_service_module, "KnowledgeRAGService", FakeKnowledgeRAGService)
    monkeypatch.setattr(settings, "COGNIA_KNOWLEDGE_BASE_IDS", [10])
    monkeypatch.setattr(settings, "COGNIA_CLIENT_APPLICATION_ID", 42)
    monkeypatch.setattr(settings, "CHAT_COGNIA_DEFAULT_KNOWLEDGE_BASE_ID", None)
    monkeypatch.setattr(settings, "CHAT_COGNIA_WRITE_SCOPE", "clientApplication")
    monkeypatch.setattr(settings, "CHAT_COGNIA_WRITE_ENABLED", True)

    intent = ToolIntent(
        "cognia_register_knowledge",
        "cognia_knowledge_write",
        "register_knowledge",
        "cognia",
        {
            "knowledge_base_id": None,
            "knowledge_type": "text",
            "title": "Nginx recovery",
            "content": "Validated steps",
            "scope_type": None,
            "subject_namespace": None,
            "external_subject_id": None,
            "tag_ids": [5, 8],
            "category_ids": [20],
            "metadata": {"owner": "operations"},
        },
        True,
        "medium",
    )

    result = await ChatbotService()._execute_cognia_write(intent, session_id="session-1")

    assert result["knowledge_base_id"] == 10
    call = FakeKnowledgeRAGService.calls[0]
    assert call[0] == "register"
    kwargs = call[1]
    assert kwargs["scope"] == {"type": "clientApplication", "clientApplicationId": 42}
    assert kwargs["knowledge_type"] == "text"
    assert kwargs["tag_ids"] == [5, 8]
    assert kwargs["category_ids"] == [20]
    assert kwargs["metadata"] == {"owner": "operations", "source": "aiops-chatbot"}
    assert kwargs["idempotency_key"].startswith("chatbot-")
    assert result["revision_id"] == 12001
    assert result["processing"] == {"state": "Processing"}
    assert result["searchable"] is False
    assert [row[0] for row in FakeKnowledgeRAGService.calls] == ["register", "processing"]


@pytest.mark.asyncio
async def test_chatbot_cognia_revision_reads_current_candidate_before_write(monkeypatch):
    monkeypatch.setattr(chatbot_service_module, "KnowledgeRAGService", FakeKnowledgeRAGService)
    monkeypatch.setattr(settings, "COGNIA_KNOWLEDGE_BASE_IDS", [10])
    monkeypatch.setattr(settings, "CHAT_COGNIA_DEFAULT_KNOWLEDGE_BASE_ID", 10)
    monkeypatch.setattr(settings, "CHAT_COGNIA_WRITE_ENABLED", True)

    intent = ToolIntent(
        "cognia_create_revision",
        "cognia_knowledge_write",
        "create_revision",
        "cognia",
        {
            "knowledge_base_id": None,
            "knowledge_id": 9001,
            "title": "Nginx recovery v2",
            "content": "Updated validated steps",
        },
        True,
        "medium",
    )

    result = await ChatbotService()._execute_cognia_write(intent, session_id="session-1")

    assert result["knowledge_id"] == 9001
    assert [row[0] for row in FakeKnowledgeRAGService.calls] == ["detail", "revision", "processing"]
    revision_kwargs = FakeKnowledgeRAGService.calls[1][1]
    assert revision_kwargs["expected_current_candidate_revision_id"] == 12001


def test_chatbot_cognia_write_rejects_ambiguous_kb(monkeypatch):
    monkeypatch.setattr(settings, "COGNIA_KNOWLEDGE_BASE_IDS", [10, 20])
    monkeypatch.setattr(settings, "CHAT_COGNIA_DEFAULT_KNOWLEDGE_BASE_ID", None)
    with pytest.raises(ValueError, match="cognia_knowledge_base_required"):
        ChatbotService._resolve_cognia_kb_id(None)


@pytest.mark.asyncio
async def test_chatbot_cognia_external_subject_scope_is_server_bound(monkeypatch):
    monkeypatch.setattr(chatbot_service_module, "KnowledgeRAGService", FakeKnowledgeRAGService)
    monkeypatch.setattr(settings, "COGNIA_KNOWLEDGE_BASE_IDS", [10])
    monkeypatch.setattr(settings, "COGNIA_CLIENT_APPLICATION_ID", 42)
    monkeypatch.setattr(settings, "CHAT_COGNIA_DEFAULT_KNOWLEDGE_BASE_ID", 10)
    monkeypatch.setattr(settings, "CHAT_COGNIA_WRITE_SCOPE", "clientApplication")
    monkeypatch.setattr(settings, "CHAT_COGNIA_WRITE_ENABLED", True)

    intent = ToolIntent(
        "cognia_register_knowledge",
        "cognia_knowledge_write",
        "register_knowledge",
        "cognia",
        {
            "knowledge_base_id": 10,
            "knowledge_type": "text",
            "title": "Ticket recovery note",
            "content": "Validated resolution",
            "scope_type": "externalSubject",
            "subject_namespace": "ticket",
            "external_subject_id": "TCK-55301",
            "tag_ids": [],
            "category_ids": [],
            "metadata": {},
        },
        True,
        "medium",
    )

    await ChatbotService()._execute_cognia_write(intent, session_id="session-1")
    kwargs = FakeKnowledgeRAGService.calls[0][1]
    assert kwargs["scope"] == {
        "type": "externalSubject",
        "clientApplicationId": 42,
        "subjectNamespace": "ticket",
        "externalSubjectId": "TCK-55301",
    }


@pytest.mark.asyncio
async def test_chatbot_cognia_processing_status_is_read_only(monkeypatch):
    monkeypatch.setattr(chatbot_service_module, "KnowledgeRAGService", FakeKnowledgeRAGService)
    monkeypatch.setattr(settings, "COGNIA_KNOWLEDGE_BASE_IDS", [10])
    intent = ToolIntent(
        "cognia_processing_status",
        "cognia_knowledge_read",
        "processing_status",
        "cognia",
        {"knowledge_base_id": 10, "knowledge_id": 9001, "revision_id": 12001},
        False,
        "low",
    )
    result = await ChatbotService()._execute_read(intent, "session-1")
    assert result["result"] == {"state": "Processing"}
    assert result["knowledge_id"] == 9001
    assert result["revision_id"] == 12001



class _ScalarRows:
    def __init__(self, rows):
        self._rows = rows

    def scalars(self):
        return self

    def all(self):
        return list(self._rows)


class _FakeIncidentDB:
    def __init__(self, incident, findings=None, evidence=None):
        self.incident = incident
        self._results = [
            _ScalarRows(findings or []),
            _ScalarRows(evidence or []),
        ]

    async def get(self, model, identifier):
        return self.incident

    async def execute(self, statement):
        return self._results.pop(0)


@pytest.mark.asyncio
async def test_verified_incident_draft_uses_durable_summary_and_provenance_not_raw_payload():
    incident_id = uuid4()
    incident = SimpleNamespace(
        id=incident_id,
        service="nginx",
        severity="average",
        status="resolved",
        summary="Port 86 was down",
        context={
            "latest_operational_outcome": {
                "action": "start_service",
                "target": "10.100.6.199",
                "execution_success": True,
                "verified": True,
                "verification": {
                    "status": "success",
                    "summary": "nginx active and port 86 listening",
                },
                "memory_id": "22222222-2222-2222-2222-222222222222",
            }
        },
    )
    findings = [
        SimpleNamespace(
            finding_type="analysis",
            statement="nginx was inactive",
            agent="vm",
            confidence=0.95,
            evidence_ids=["vm:service:1"],
            created_at=None,
        )
    ]
    evidence = [
        SimpleNamespace(
            source="vm_mcp",
            type="event",
            reference="vm:service:1",
            confidence=1.0,
            raw_data={"password": "must-not-be-published"},
            created_at=None,
        )
    ]
    db = _FakeIncidentDB(incident, findings, evidence)

    draft = await ChatbotService()._verified_incident_knowledge_draft(
        db,
        str(incident_id),
    )

    assert "nginx was inactive" in draft["content"]
    assert "start_service" in draft["content"]
    assert "vm:service:1" in draft["content"]
    assert "must-not-be-published" not in draft["content"]
    assert draft["metadata"]["verified"] == "true"
    assert draft["metadata"]["incidentId"] == str(incident_id)


@pytest.mark.asyncio
async def test_unverified_incident_cannot_be_published_to_cognia():
    incident_id = uuid4()
    incident = SimpleNamespace(
        id=incident_id,
        service="nginx",
        severity="average",
        status="escalated",
        summary="Diagnosis incomplete",
        context={
            "latest_operational_outcome": {
                "action": "start_service",
                "target": "10.100.6.199",
                "execution_success": True,
                "verified": False,
                "verification": {"status": "inconclusive"},
            }
        },
    )
    db = _FakeIncidentDB(incident)

    with pytest.raises(ValueError, match="incident_not_verified_for_knowledge_publication"):
        await ChatbotService()._verified_incident_knowledge_draft(
            db,
            str(incident_id),
        )
