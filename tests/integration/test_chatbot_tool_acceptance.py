import os

import pytest
from fastapi import HTTPException
from sqlalchemy import text

from apps.chatbot.models import ChatMessageRequest
from apps.chatbot.service import ChatbotService
from apps.chatbot.store import ChatStore
from apps.security.oidc import Identity
from database import AsyncSessionLocal
from integrations.llm.base import LLMAdapter, LLMResponse
from integrations.zabbix.mcp_client import ZabbixMCPClient


pytestmark = pytest.mark.skipif(
    os.getenv("RUN_DB_CHATBOT_TEST") != "1",
    reason="requires migrated PostgreSQL acceptance database",
)


class ToolSelectingLLM(LLMAdapter):
    def __init__(self, tool_name: str, arguments: str, summary: str = "validated tool summary"):
        self.tool_name = tool_name
        self.arguments = arguments
        self.summary = summary
        self.summary_prompts = []

    @property
    def provider_name(self) -> str:
        return "chatbot-tool-acceptance"

    async def generate(self, prompt, system_prompt=None, temperature=0.7, max_tokens=1000, **kwargs):
        self.summary_prompts.append(prompt)
        if kwargs.get("stage") == "chatbot_answer_validation":
            return LLMResponse(
                content='{"valid":true,"question_answered":true,"evidence_sufficient":true,'
                        '"claims_grounded":true,"hallucination_risk":"low","tool_usage_complete":true,'
                        '"missing_capabilities":[],"missing_evidence":[],"contradictions":[],'
                        '"unsupported_claims":[],"needs_replan":false,"needs_user_clarification":false,'
                        '"rewrite_required":false,"confidence":0.95,"reason":"test-grounded"}',
                model="chatbot-tool-acceptance",
            )
        return LLMResponse(content=self.summary, model="chatbot-tool-acceptance")

    async def generate_with_messages(self, messages, temperature=0.7, max_tokens=1000, **kwargs):
        return LLMResponse(
            content="",
            model="chatbot-tool-acceptance",
            tool_calls=[
                {
                    "id": "call-1",
                    "type": "function",
                    "function": {"name": self.tool_name, "arguments": self.arguments},
                }
            ],
        )


async def _cleanup(owner: str) -> None:
    async with AsyncSessionLocal() as db:
        await db.execute(text("DELETE FROM chat_sessions WHERE owner_subject=:owner"), {"owner": owner})
        await db.execute(
            text("DELETE FROM incidents WHERE source='chatbot' AND context->'chatbot'->>'requested_by'=:owner"),
            {"owner": owner},
        )
        await db.execute(text("DELETE FROM audit_events WHERE actor=:owner"), {"owner": owner})
        await db.commit()


class _FakeAlert:
    def model_dump(self, mode="json"):
        return {
            "source": "zabbix",
            "source_id": "123",
            "severity": "high",
            "service": "payments",
            "message": "CPU high",
            "timestamp": "2026-09-17T08:00:00Z",
            "raw_data": {},
        }


@pytest.mark.asyncio(loop_scope="session")
async def test_zabbix_read_uses_allowlisted_mcp_adapter_and_writes_audit(monkeypatch):
    owner = "chat-zabbix-viewer"
    identity = Identity(subject=owner, roles=("viewer",))
    llm = ToolSelectingLLM("zabbix_problems", '{"service":"payments","limit":10}', "one active Zabbix problem")
    observed = {}

    async def fake_get_alerts(self, since=None, service=None, limit=100):
        observed.update(service=service, limit=limit)
        return [_FakeAlert()]

    monkeypatch.setattr(ZabbixMCPClient, "get_alerts", fake_get_alerts)
    response = await ChatbotService(llm).message(identity, ChatMessageRequest(message="مشکل‌های زبیکس payments رو بگو"))
    assert response.kind == "tool_result"
    assert response.source == "zabbix_mcp"
    assert observed == {"service": "payments", "limit": 10}
    assert response.data[0]["message"] == "CPU high"

    async with AsyncSessionLocal() as db:
        events = (
            await db.execute(
                text("SELECT event_type FROM audit_events WHERE actor=:owner ORDER BY created_at"),
                {"owner": owner},
            )
        ).scalars().all()
        assert "chat_evidence_collected" in events
        assert "chat_final_answer" in events
    await _cleanup(owner)


@pytest.mark.asyncio(loop_scope="session")
async def test_kubernetes_read_stays_behind_mcp_client(monkeypatch):
    owner = "chat-k8s-viewer"
    identity = Identity(subject=owner, roles=("viewer",))
    llm = ToolSelectingLLM(
        "kubernetes_read",
        '{"operation":"list_pods","namespace":"payments"}',
        "payments has one running pod",
    )
    observed = {}

    class FakeKubernetesMCPClient:
        async def collect_query(self, *, operation, namespace, service=None, resource=None):
            observed.update(operation=operation, namespace=namespace, service=service, resource=resource)
            return [{"name": "payment-api-1", "phase": "Running"}]

    monkeypatch.setattr("apps.chatbot.service.KubernetesMCPClient", FakeKubernetesMCPClient)
    response = await ChatbotService(llm).message(identity, ChatMessageRequest(message="لیست پادهای payments رو بده"))
    assert response.kind == "tool_result"
    assert response.source == "kubernetes_mcp"
    assert observed["operation"] == "list_pods"
    assert observed["namespace"] == "payments"
    assert response.data[0]["name"] == "payment-api-1"
    await _cleanup(owner)


@pytest.mark.asyncio(loop_scope="session")
@pytest.mark.parametrize("failure", [TimeoutError("timeout"), RuntimeError("mcp unavailable")])
async def test_tool_timeout_or_mcp_failure_returns_guarded_answer_without_fabricated_state(monkeypatch, failure):
    owner = f"chat-tool-failure-{type(failure).__name__.lower()}"
    identity = Identity(subject=owner, roles=("viewer",))
    llm = ToolSelectingLLM("vm_metrics", '{"target":"vm01"}')

    async def fail_read(self, intent, session_id):
        raise failure

    monkeypatch.setattr(ChatbotService, "_execute_read", fail_read)
    response = await ChatbotService(llm).message(identity, ChatMessageRequest(message="cpu vm01 چقدره؟"))
    assert response.kind == "tool_result"
    assert "امکان تأیید وضعیت واقعی" in response.message
    assert "cpu_percent" not in response.message
    assert "41" not in response.message
    await _cleanup(owner)


@pytest.mark.asyncio(loop_scope="session")
async def test_tool_payload_secrets_are_redacted_before_llm_history_and_ui(monkeypatch):
    owner = "chat-secret-redaction"
    identity = Identity(subject=owner, roles=("viewer",))
    llm = ToolSelectingLLM(
        "vm_service_logs",
        '{"target":"vm01","service":"nginx","limit":20}',
        "nginx log contains password=hunter2 token:abc123 but status is healthy",
    )

    async def fake_read(self, intent, session_id):
        return {
            "source": "vm_mcp",
            "result": {"log": "startup password=hunter2 token:abc123 x-api-key=key-789 service=nginx"},
        }

    monkeypatch.setattr(ChatbotService, "_execute_read", fake_read)
    response = await ChatbotService(llm).message(identity, ChatMessageRequest(message="لاگ nginx روی vm01 رو بررسی کن"))
    assert "hunter2" not in response.message
    assert "abc123" not in response.message
    assert "hunter2" not in response.data["log"]
    assert "key-789" not in response.data["log"]
    assert llm.summary_prompts
    assert "hunter2" not in llm.summary_prompts[-1]
    assert "abc123" not in llm.summary_prompts[-1]

    async with AsyncSessionLocal() as db:
        rows = await ChatStore(db).history(response.session_id)
        persisted = "\n".join(str(row["content"]) for row in rows)
        assert "hunter2" not in persisted
        assert "abc123" not in persisted
        assert "key-789" not in persisted
    await _cleanup(owner)
