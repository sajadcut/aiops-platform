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
        return {"knowledgeId": kwargs["knowledge_id"], "revisionId": 12002, "status": "Processing"}


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
        {"knowledge_base_id": None, "title": "Nginx recovery", "content": "Validated steps"},
        True,
        "medium",
    )

    result = await ChatbotService()._execute_cognia_write(intent, session_id="session-1")

    assert result["knowledge_base_id"] == 10
    call = FakeKnowledgeRAGService.calls[0]
    assert call[0] == "register"
    kwargs = call[1]
    assert kwargs["scope"] == {"type": "clientApplication", "clientApplicationId": 42}
    assert kwargs["idempotency_key"].startswith("chatbot-")
    assert kwargs["metadata"] == {"source": "aiops-chatbot"}


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
    assert [row[0] for row in FakeKnowledgeRAGService.calls] == ["detail", "revision"]
    revision_kwargs = FakeKnowledgeRAGService.calls[1][1]
    assert revision_kwargs["expected_current_candidate_revision_id"] == 12001


def test_chatbot_cognia_write_rejects_ambiguous_kb(monkeypatch):
    monkeypatch.setattr(settings, "COGNIA_KNOWLEDGE_BASE_IDS", [10, 20])
    monkeypatch.setattr(settings, "CHAT_COGNIA_DEFAULT_KNOWLEDGE_BASE_ID", None)
    with pytest.raises(ValueError, match="cognia_knowledge_base_required"):
        ChatbotService._resolve_cognia_kb_id(None)
