from uuid import uuid4

from apps.chatbot.models import ChatHistoryMessage, ChatMessageResponse
from domain.contracts.redaction import REDACTED


def test_chatbot_response_redacts_inline_secrets_before_ui_serialization():
    response = ChatMessageResponse(
        session_id=uuid4(),
        kind="tool_result",
        message="diagnostic password=hunter2 token:abc123",
        data={"log": "x-api-key=key-789 service=payments", "nested": {"client_secret": "value"}},
    )
    assert "hunter2" not in response.message
    assert "abc123" not in response.message
    assert response.message.count(REDACTED) == 2
    assert "key-789" not in response.data["log"]
    assert response.data["nested"]["client_secret"] == REDACTED
    assert "service=payments" in response.data["log"]


def test_chat_history_response_applies_same_redaction_defense_in_depth():
    item = ChatHistoryMessage(
        role="assistant",
        content="password=secret-value status=ok",
        created_at="2026-09-17T00:00:00+00:00",
        metadata={"token": "never-return-this", "kind": "answer"},
    )
    assert "secret-value" not in item.content
    assert "status=ok" in item.content
    assert item.metadata["token"] == REDACTED
